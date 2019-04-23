/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2018 Cloudbyte. All rights reserved.
 */

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/dsl_destroy.h>
#include <sys/dsl_dir.h>
#include <uzfs_io.h>
#include <uzfs_rebuilding.h>
#include <zrepl_mgmt.h>
#include <uzfs_mgmt.h>
#include "mgmt_conn.h"
#include "data_conn.h"

#define	MAXEVENTS 64

#define	IO_THRESHOLD_TIME	30
#define	ZVOL_REBUILD_STEP_SIZE  (10 * 1024ULL * 1024ULL * 1024ULL) // 10GB
uint64_t zvol_rebuild_step_size = ZVOL_REBUILD_STEP_SIZE;

#define	REBUILD_CMD_QUEUE_MAX_LIMIT (100)
uint64_t zvol_rebuild_cmd_queue_limit = REBUILD_CMD_QUEUE_MAX_LIMIT;

#define	IS_REBUILD_HIT_MAX_CMD_LIMIT(zinfo)	\
	((zinfo->rebuild_cmd_queued_cnt -	\
	    zinfo->rebuild_cmd_acked_cnt) >	\
	    zvol_rebuild_cmd_queue_limit)

uint16_t io_server_port = IO_SERVER_PORT;
uint16_t rebuild_io_server_port = REBUILD_IO_SERVER_PORT;

kcondvar_t timer_cv;
kmutex_t timer_mtx;

typedef struct singly_node_list_s {
	void *node;
	SLIST_ENTRY(singly_node_list_s) node_next;
} singly_node_list_t;

SLIST_HEAD(singly_node_list, singly_node_list_s);

/*
 * Allocate zio command along with
 * buffer needed for IO completion.
 */
zvol_io_cmd_t *
zio_cmd_alloc(zvol_io_hdr_t *hdr, int fd)
{
	zvol_io_cmd_t *zio_cmd = kmem_zalloc(
	    sizeof (zvol_io_cmd_t), KM_SLEEP);

	bcopy(hdr, &zio_cmd->hdr, sizeof (zio_cmd->hdr));

	if (hdr->len != 0) {
		zio_cmd->buf = kmem_zalloc(sizeof (char) * hdr->len, KM_SLEEP);
		zio_cmd->buf_len = hdr->len;
		ASSERT((hdr->opcode == ZVOL_OPCODE_READ) ||
		    (hdr->opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr->opcode == ZVOL_OPCODE_OPEN) ||
		    (hdr->opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE));
	}
	zio_cmd->conn = fd;
	return (zio_cmd);
}

void
quiesce_wait(zvol_info_t *zinfo)
{
	while (1) {
		if (zinfo->quiesce_done ||
		    !taskq_check_active_ios(
		    zinfo->uzfs_zvol_taskq)) {
			zinfo->quiesce_done = 1;
			zinfo->quiesce_requested = 0;
			return;
		}
		else
			sleep(1);
	}
}

/*
 * Free zio command along with buffer.
 */
void
zio_cmd_free(zvol_io_cmd_t **cmd)
{
	zvol_io_cmd_t *zio_cmd = *cmd;
	zvol_op_code_t opcode = zio_cmd->hdr.opcode;
	switch (opcode) {
		case ZVOL_OPCODE_READ:
		case ZVOL_OPCODE_WRITE:
		case ZVOL_OPCODE_OPEN:
		case ZVOL_OPCODE_REBUILD_SNAP_DONE:
			if (zio_cmd->buf != NULL) {
				kmem_free(zio_cmd->buf, zio_cmd->buf_len);
			}
			break;

		case ZVOL_OPCODE_SYNC:
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
		case ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE:
			/* Nothing to do */
			break;

		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	kmem_free(zio_cmd, sizeof (zvol_io_cmd_t));
	*cmd = NULL;
}

/*
 * This API is to read data from "blocking" sockets
 * Returns 0 on success, -1 on error
 */
int
uzfs_zvol_socket_read(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = read(fd, (void *)p, nbytes);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			LOG_ERRNO("Socket(%d) read error", fd);
			return (-1);
		} else if (count == 0) {
			LOG_INFO("Connection closed by the peer for socket(%d)",
			    fd);
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
}

/*
 * Read header message from socket in safe manner, which is: first we read a
 * version number and if valid then we read the rest of the message.
 *
 * Return value < 0 => error
 *              > 0 => invalid version
 *              = 0 => ok
 */
int
uzfs_zvol_read_header(int fd, zvol_io_hdr_t *hdr)
{
	int rc;

	rc = uzfs_zvol_socket_read(fd, (char *)hdr,
	    sizeof (hdr->version));
	if (rc != 0)
		return (-1);

	if (hdr->version != REPLICA_VERSION) {
		LOG_ERR("invalid replica protocol version %d",
		    hdr->version);
		return (1);
	}
	rc = uzfs_zvol_socket_read(fd,
	    ((char *)hdr) + sizeof (hdr->version),
	    sizeof (*hdr) - sizeof (hdr->version));
	if (rc != 0)
		return (-1);

	return (0);
}

/*
 * This API is to write data from "blocking" sockets
 * Returns 0 on success, -1 on error
 */
int
uzfs_zvol_socket_write(int fd, char *buf, uint64_t nbytes)
{
	ssize_t count = 0;
	char *p = buf;
	while (nbytes) {
		count = write(fd, (void *)p, nbytes);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			LOG_ERRNO("Socket write error");
			return (-1);
		}
		p += count;
		nbytes -= count;
	}
	return (0);
}

/*
 * We expect only one chunk of data with meta header in write request.
 * Nevertheless the code is general to handle even more of them.
 */
static int
uzfs_submit_writes(zvol_info_t *zinfo, zvol_io_cmd_t *zio_cmd)
{
	blk_metadata_t	metadata;
	boolean_t	is_rebuild = B_FALSE;
	zvol_io_hdr_t 	*hdr = &zio_cmd->hdr;
	struct zvol_io_rw_hdr *write_hdr;
	char	*datap = (char *)zio_cmd->buf;
	size_t	data_offset = hdr->offset;
	size_t	remain = hdr->len;
	int	rc = 0;
	uint64_t running_ionum;
	is_rebuild = hdr->flags & ZVOL_OP_FLAG_REBUILD;

#ifdef DEBUG
	if (is_rebuild) {
		ASSERT(ZVOL_IS_REBUILDING(zinfo->main_zv) ||
		    (zinfo->main_zv->rebuild_info.rebuild_cnt > 1));
		ASSERT(ZINFO_IS_DEGRADED(zinfo));
	}
#endif

	while (remain > 0) {
		if (remain < sizeof (*write_hdr))
			return (-1);

		write_hdr = (struct zvol_io_rw_hdr *)datap;
		metadata.io_num = write_hdr->io_num;

		datap += sizeof (*write_hdr);
		remain -= sizeof (*write_hdr);
		if (remain < write_hdr->len)
			return (-1);
		/*
		 * Write to main_zv when volume is either
		 * healthy or in REBUILD_AFS state of rebuild
		 */
		if (ZVOL_IS_HEALTHY(zinfo->main_zv) || is_rebuild ||
		    ZVOL_IS_REBUILDING_AFS(zinfo->main_zv)) {
			rc = uzfs_write_data(zinfo->main_zv, datap, data_offset,
			    write_hdr->len, &metadata, is_rebuild);
			if (rc != 0)
				break;
		}

		/* IO to clone should be sent only when it is from app */
		if (!is_rebuild && !ZVOL_IS_HEALTHY(zinfo->main_zv)) {
			rc = uzfs_write_data(zinfo->clone_zv, datap,
			    data_offset, write_hdr->len, &metadata,
			    is_rebuild);
			if (rc != 0)
				break;
		}
		/* Update the highest ionum used for checkpointing */
		running_ionum = zinfo->running_ionum;
		while (running_ionum < write_hdr->io_num) {
			atomic_cas_64(&zinfo->running_ionum, running_ionum,
			    write_hdr->io_num);
			running_ionum = zinfo->running_ionum;
		}

		datap += write_hdr->len;
		remain -= write_hdr->len;
		data_offset += write_hdr->len;
	}

	return (rc);
}

/*
 * zvol worker is responsible for actual work.
 * It execute read/write/sync command to uzfs.
 * It enqueue command to completion queue and
 * send signal to ack-sender thread.
 *
 * Write commands that are for rebuild will not
 * be enqueued. Also, commands memory is
 * maintained by its caller.
 */
void
uzfs_zvol_worker(void *arg)
{
	zvol_io_cmd_t	*zio_cmd;
	zvol_info_t	*zinfo;
	zvol_state_t	*zvol_state, *read_zv;
	zvol_io_hdr_t 	*hdr;
	metadata_desc_t	**metadata_desc;
	int		rc = 0;
	boolean_t	rebuild_cmd_req;
	boolean_t	read_metadata;

	zio_cmd = (zvol_io_cmd_t *)arg;
	hdr = &zio_cmd->hdr;
	zinfo = zio_cmd->zinfo;
	zvol_state = zinfo->main_zv;
	rebuild_cmd_req = hdr->flags & ZVOL_OP_FLAG_REBUILD;
	read_metadata = hdr->flags & ZVOL_OP_FLAG_READ_METADATA;

	if (!zinfo->is_io_ack_sender_created) {
		if (!(rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)))
			zio_cmd_free(&zio_cmd);
		if (hdr->opcode == ZVOL_OPCODE_WRITE)
			atomic_inc_64(&zinfo->write_req_received_cnt);
		goto drop_refcount;
	}

	/*
	 * For rebuild case, do not free zio_cmd
	 */
	if (zinfo->state == ZVOL_INFO_STATE_OFFLINE) {
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
		if (!(rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)))
			zio_cmd_free(&zio_cmd);
		goto drop_refcount;
	}

	atomic_inc_64(&zinfo->inflight_io_cnt);

	/*
	 * If zvol hasn't passed rebuild phase or if read
	 * is meant for rebuild or if target has asked for metadata
	 * then we need the metadata
	 */
	if ((!rebuild_cmd_req && ZVOL_IS_REBUILDED(zvol_state)) &&
	    !read_metadata) {
		metadata_desc = NULL;
		zio_cmd->metadata_desc = NULL;
	} else {
		metadata_desc = &zio_cmd->metadata_desc;
	}

	zio_cmd->io_start_time = gethrtime();

	switch (hdr->opcode) {
		case ZVOL_OPCODE_READ:
			read_zv = zinfo->main_zv;
			if (rebuild_cmd_req) {
				/*
				 * if we are rebuilding, we have
				 * to read the data from the snapshot
				 */
				if (zinfo->rebuild_zv) {
					read_zv = zinfo->rebuild_zv;
				} else {
					rc = -1;
					break;
				}
			} else if (!ZVOL_IS_HEALTHY(zinfo->main_zv))
				/* App IOs should go to clone_zv */
				read_zv = zinfo->clone_zv;

			rc = uzfs_read_data(read_zv,
			    (char *)zio_cmd->buf,
			    hdr->offset, hdr->len,
			    metadata_desc);

			atomic_inc_64(&zinfo->read_req_received_cnt);
			break;

		case ZVOL_OPCODE_WRITE:
			rc = uzfs_submit_writes(zinfo, zio_cmd);
			atomic_inc_64(&zinfo->write_req_received_cnt);
			break;

		case ZVOL_OPCODE_SYNC:
			if (ZVOL_IS_HEALTHY(zinfo->main_zv) ||
			    ZVOL_IS_REBUILDING_AFS(zinfo->main_zv)) {
				uzfs_flush_data(zinfo->main_zv);
			}
			if (!ZVOL_IS_HEALTHY(zinfo->main_zv))
				uzfs_flush_data(zinfo->clone_zv);
			atomic_inc_64(&zinfo->sync_req_received_cnt);
			break;

		case ZVOL_OPCODE_REBUILD_SNAP_DONE:
		case ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE:
		case ZVOL_OPCODE_REBUILD_STEP_DONE:
			break;
		default:
			VERIFY(!"Should be a valid opcode");
			break;
	}

	if (rc != 0) {
		LOG_ERR("OP code %d failed: %d", hdr->opcode, rc);
		hdr->status = ZVOL_OP_STATUS_FAILED;
		hdr->len = 0;
	} else {
		hdr->status = ZVOL_OP_STATUS_OK;
	}

	/*
	 * We are not sending ACK for writes meant for rebuild
	 */
	if (rebuild_cmd_req && (hdr->opcode == ZVOL_OPCODE_WRITE)) {
		goto drop_refcount;
	}

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	if (!zinfo->is_io_ack_sender_created) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		zio_cmd_free(&zio_cmd);
		goto drop_refcount;
	}
	STAILQ_INSERT_TAIL(&zinfo->complete_queue, zio_cmd, cmd_link);

	if (zinfo->io_ack_waiting) {
		rc = pthread_cond_signal(&zinfo->io_ack_cond);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

drop_refcount:
	atomic_add_64(&zinfo->inflight_io_cnt, -1);
	atomic_add_64(&zinfo->dispatched_io_cnt, -1);

	uzfs_zinfo_drop_refcnt(zinfo);
}

static void
uzfs_zvol_append_to_fd_list(zvol_info_t *zinfo, int fd)
{
	zinfo_fd_t *new_zinfo_fd = kmem_alloc(sizeof (zinfo_fd_t), KM_SLEEP);
	new_zinfo_fd->fd = fd;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
#ifdef DEBUG
	zinfo_fd_t *zinfo_fd = NULL;
	STAILQ_FOREACH(zinfo_fd, &zinfo->fd_list, fd_link) {
		if (zinfo_fd->fd == fd) {
			ASSERT(1 == 0);
		}
	}
#endif
	STAILQ_INSERT_TAIL(&zinfo->fd_list, new_zinfo_fd, fd_link);
	LOG_DEBUG("Appending fd %d for zvol %s", fd, zinfo->name);
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

static void
uzfs_zvol_remove_from_fd_list(zvol_info_t *zinfo, int fd)
{
	zinfo_fd_t *zinfo_fd = NULL;

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
#ifdef DEBUG
	int count = 0;
	STAILQ_FOREACH(zinfo_fd, &zinfo->fd_list, fd_link) {
		if (zinfo_fd->fd == fd)
			count++;
	}
	ASSERT(count == 1);
#endif
	zinfo_fd = STAILQ_FIRST(&zinfo->fd_list);
	while (zinfo_fd != NULL) {
		if (zinfo_fd->fd == fd) {
			STAILQ_REMOVE(&zinfo->fd_list, zinfo_fd,
			    zinfo_fd_s, fd_link);
			kmem_free(zinfo_fd, sizeof (zinfo_fd_t));
			break;
		}
		zinfo_fd = STAILQ_NEXT(zinfo_fd, fd_link);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

int
uzfs_zvol_handle_rebuild_snap_done(zvol_io_hdr_t *hdrp,
    int sfd, zvol_info_t *zinfo)
{
	int rc = 0;
	char *snap;
	char zvol_name[MAX_NAME_LEN + 1];
#if !defined(DEBUG)
	char *local_vol = NULL, *remote_vol = NULL;
#endif

	if (hdrp->len == 0 || hdrp->len > MAX_NAME_LEN) {
		LOG_ERR("Unexpected hdr.len:%ld on volume: %s",
		    hdrp->len, zinfo->name);
		return (rc = -1);
	}

	if ((rc = uzfs_zvol_socket_read(sfd, zvol_name, hdrp->len)) != 0)
		return (rc);

	zvol_name[hdrp->len] = '\0';
	snap = strchr(zvol_name, '@');
	if (snap == NULL) {
		LOG_ERR("Invalid snapshot name: %s", zvol_name);
		return (rc = -1);
	}

	*snap++ = '\0';

#if !defined(DEBUG)
	local_vol = strchr(zinfo->name, '/');
	remote_vol = strchr(zvol_name, '/');

	if (local_vol == NULL || remote_vol == NULL) {
		LOG_ERR("Invalid volume name, Received name: %s, Expected:%s",
		    zvol_name, zinfo->name);
		return (rc = -1);
	}

	if (strcmp(local_vol + 1, remote_vol + 1) != 0) {
		LOG_ERR("Wrong volume, Received name: %s, Expected:%s",
		    zvol_name, zinfo->name);
		return (rc = -1);
	}
#endif
	rc = uzfs_zvol_create_snapshot_update_zap(zinfo, snap, hdrp->io_seq);
	if (rc != 0) {
		LOG_ERR("Failed to create %s@%s: %d", zinfo->name, snap, rc);
	}
	return (rc);
}

void
uzfs_zvol_rebuild_dw_replica(void *arg)
{
	rebuild_thread_arg_t *rebuild_args = arg;
	struct sockaddr_in replica_ip;

	int		start_rebuild_from_clone = 0;
	int		rc = 0;
	int		sfd = -1;
	uint64_t	offset = 0;
	uint64_t	checkpointed_ionum;
	boolean_t 	all_snap_done = B_FALSE;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zvol_state;
	zvol_io_cmd_t	*zio_cmd = NULL;
	zvol_io_hdr_t 	hdr;
	struct linger lo = { 1, 0 };

	sfd = rebuild_args->fd;
	zinfo = rebuild_args->zinfo;

	uzfs_zvol_append_to_fd_list(zinfo, sfd);

	if ((rc = setsockopt(sfd, SOL_SOCKET, SO_LINGER, &lo, sizeof (lo)))
	    != 0) {
		LOG_ERRNO("setsockopt failed for sock(%d)", sfd);
		goto exit;
	}

	bzero(&replica_ip, sizeof (replica_ip));
	replica_ip.sin_family = AF_INET;
	replica_ip.sin_addr.s_addr = inet_addr(rebuild_args->ip);
	replica_ip.sin_port = htons(rebuild_args->port);

	if ((rc = connect(sfd, (struct sockaddr *)&replica_ip,
	    sizeof (replica_ip))) != 0) {
		LOG_ERRNO("connect failed on fd(%d) to %s:%u", sfd,
		    rebuild_args->ip, rebuild_args->port);
		perror("connect");
		goto exit;
	}

	rc = set_socket_keepalive(sfd);
	if (rc != 0)
		LOG_ERR("keepalive errored on connected rebuild fd %d", sfd);
	rc = 0;

	/* Set state in-progess state now */
	rc = uzfs_zvol_get_last_committed_io_no(
	    zinfo->main_zv, HEALTHY_IO_SEQNUM, &checkpointed_ionum);
	if (rc != 0) {
		LOG_ERR("Unable to get checkpointed num on zvol:%s",
		    zinfo->name);
		goto exit;
	}

	zvol_state = zinfo->main_zv;
	bzero(&hdr, sizeof (hdr));
	hdr.status = ZVOL_OP_STATUS_OK;
	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_HANDSHAKE;
	hdr.len = strlen(rebuild_args->zvol_name) + 1;

	rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
	if (rc != 0) {
		LOG_ERR("Socket hdr write failed for fd(%d) during %s "
		    "rebuilding", sfd, zinfo->name);
		goto exit;
	}

	rc = uzfs_zvol_socket_write(sfd, (void *)rebuild_args->zvol_name,
	    hdr.len);
	if (rc != 0) {
		LOG_ERR("Socket handshake write failed for fd(%d) during %s "
		    "rebuilding", sfd, zinfo->name);
		goto exit;
	}

next_step:

	if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
		LOG_ERR("rebuilding errored.. for %s.. on sock(%d)",
		    zinfo->name, sfd);
		rc = -1;
		goto exit;
	}

	/* One more snapshot has been transferred */
	if (hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE) {
#ifdef DEBUG
		if (inject_error.delay.downgraded_replica_rebuild_size_set == 1)
			offset = ZVOL_VOLUME_SIZE(zvol_state) + 1;
#endif
		ASSERT(offset >= ZVOL_VOLUME_SIZE(zvol_state));
		rc = uzfs_zvol_handle_rebuild_snap_done(&hdr,
		    sfd, zinfo);
		if (rc != 0) {
			LOG_ERR("Rebuild snap_done failed.. for %s on fd(%d)",
			    zinfo->name, sfd);
			goto exit;
		}
		offset = 0;
		rc = uzfs_zvol_get_last_committed_io_no(zinfo->main_zv,
		    HEALTHY_IO_SEQNUM, &checkpointed_ionum);
		if (rc != 0) {
			LOG_ERR("Unable to get checkpointed num on zvol:%s",
			    zinfo->name);
			goto exit;
		}
	}

	if (offset >= ZVOL_VOLUME_SIZE(zvol_state)) {
		hdr.opcode = ZVOL_OPCODE_REBUILD_COMPLETE;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERRNO("Socket rebuild_complete write failed, but,"
			    "counting as success with this replica(%s) on "
			    "fd(%d)", zinfo->name, sfd);
			rc = 0;
			goto exit;
		} else if (all_snap_done == B_TRUE) {
#ifdef DEBUG
			mutex_enter(&zinfo->main_zv->rebuild_mtx);
			ASSERT(uzfs_zvol_get_rebuild_status(zinfo->main_zv) ==
			    ZVOL_REBUILDING_AFS);
			mutex_exit(&zinfo->main_zv->rebuild_mtx);
#endif
			rc = 0;
			LOG_INFO("Rebuilding zvol %s completed", zinfo->name);
			goto exit;
		}
	} else {
		bzero(&hdr, sizeof (hdr));
		hdr.status = ZVOL_OP_STATUS_OK;
		hdr.version = REPLICA_VERSION;
		hdr.opcode = ZVOL_OPCODE_REBUILD_STEP;
		hdr.checkpointed_io_seq = checkpointed_ionum;
		hdr.offset = offset;
		if ((offset + zvol_rebuild_step_size) >
		    ZVOL_VOLUME_SIZE(zvol_state))
			hdr.len = ZVOL_VOLUME_SIZE(zvol_state) - offset;
		else
			hdr.len = zvol_rebuild_step_size;
		rc = uzfs_zvol_socket_write(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0) {
			LOG_ERR("Socket rebuild_step write failed for %s on "
			    "fd(%d)", zvol_state->zv_name, sfd);
			goto exit;
		}
	}

	while (1) {

		if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
			LOG_ERR("rebuilding already errored.. for %s..",
			    zinfo->name);
			rc = -1;
			goto exit;
		}

		rc = uzfs_zvol_socket_read(sfd, (char *)&hdr, sizeof (hdr));
		if (rc != 0)
			goto exit;

#ifdef DEBUG
		if (inject_error.inject_rebuild_error.
		    dw_replica_rebuild_error_io > 0) {
			inject_error.inject_rebuild_error.
			    dw_replica_rebuild_error_io--;
			if (inject_error.inject_rebuild_error.
			    dw_replica_rebuild_error_io ==
			    1) {
				rc = -1;
				goto exit;
			}
		}
#endif
		if (hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("received err in rebuild.. for %s..",
			    zinfo->name);
			rc = -1;
			goto exit;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_STEP_DONE) {
			offset += zvol_rebuild_step_size;
			LOG_DEBUG("ZVOL_OPCODE_REBUILD_STEP_DONE received on "
			    "fd: %d", sfd);
			goto next_step;
		}

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE)
			goto next_step;

		if (hdr.opcode == ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE) {
			LOG_DEBUG("Received ALL_SNAP_DONE on fd: %d", sfd);
			/* All snapshots has been transferred */
			all_snap_done = B_TRUE;
			/*
			 * Change rebuild state to mark that all
			 * snapshots has been transferred now
			 */
			mutex_enter(&zinfo->main_zv->rebuild_mtx);
			if (ZVOL_IS_REBUILDING_ERRORED(zinfo->main_zv)) {
				mutex_exit(&zinfo->main_zv->rebuild_mtx);
				rc = -1;
				goto exit;
			}

			/*
			 * Multiple rebuild ops going on in parallel,
			 * one of them might have changed rebuild state
			 */
			zvol_rebuild_status_t state;
			state = uzfs_zvol_get_rebuild_status(zinfo->main_zv);
			if (state != ZVOL_REBUILDING_AFS) {
				ASSERT(state == ZVOL_REBUILDING_SNAP);
				uzfs_zvol_set_rebuild_status(zinfo->main_zv,
				    ZVOL_REBUILDING_AFS);
				if (start_rebuild_from_clone == 0)
					start_rebuild_from_clone = 1;
				/*
				 * Lets ask io_receiver thread to flush
				 * all outstanding IOs in taskq
				 */
				zinfo->quiesce_done = 0;
				zinfo->quiesce_requested = 1;
			}
			mutex_exit(&zinfo->main_zv->rebuild_mtx);
			/*
			 * Wait for all outstanding IOs to be flushed
			 * to disk before making further progress
			 */
			quiesce_wait(zinfo);

			if (start_rebuild_from_clone == 1) {
				start_rebuild_from_clone = 2;
				rc = uzfs_zinfo_rebuild_from_clone(zinfo);
				if (rc != 0) {
					LOG_ERR("Rebuild from clone for vol %s "
					    "failed on fd(%d)", zinfo->name,
					    sfd);
					rc = -1;
					goto exit;
				}
				LOG_INFO("Rebuild started from clone for vol "
				    "%s on fd(%d)", zinfo->name, sfd);
			}
			continue;
		}
		ASSERT((hdr.opcode == ZVOL_OPCODE_READ) &&
		    (hdr.flags & ZVOL_OP_FLAG_REBUILD));
		hdr.opcode = ZVOL_OPCODE_WRITE;

		zio_cmd = zio_cmd_alloc(&hdr, sfd);
		rc = uzfs_zvol_socket_read(sfd, zio_cmd->buf, hdr.len);
		if (rc != 0)
			goto exit;

		/*
		 * Take refcount for uzfs_zvol_worker to work on it.
		 * Will dropped by uzfs_zvol_worker once cmd is executed.
		 */
		uzfs_zinfo_take_refcnt(zinfo);
		zio_cmd->zinfo = zinfo;
		atomic_inc_64(&zinfo->dispatched_io_cnt);
		uzfs_zvol_worker(zio_cmd);
		if (zio_cmd->hdr.status != ZVOL_OP_STATUS_OK) {
			LOG_ERR("rebuild IO failed.. for %s.. on fd(%d)",
			    zinfo->name, sfd);
			rc = -1;
			goto exit;
		}
		zio_cmd_free(&zio_cmd);
	}

exit:
	uzfs_zvol_remove_from_fd_list(zinfo, sfd);

	mutex_enter(&zinfo->main_zv->rebuild_mtx);
	if (rc != 0) {
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_ERRORED);
		(zinfo->main_zv->rebuild_info.rebuild_failed_cnt) += 1;
		LOG_ERR("uzfs_zvol_rebuild_dw_replica thread exiting, "
		    "rebuilding failed zvol: %s on fd(%d)", zinfo->name, sfd);
	}

	uint8_t wquiesce = 0;

	(zinfo->main_zv->rebuild_info.rebuild_done_cnt) += 1;
	if (zinfo->main_zv->rebuild_info.rebuild_cnt ==
	    zinfo->main_zv->rebuild_info.rebuild_done_cnt) {
		if (zinfo->main_zv->rebuild_info.rebuild_failed_cnt != 0)
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_FAILED);
		else
			wquiesce = 1;
	}
	mutex_exit(&zinfo->main_zv->rebuild_mtx);

	/*
	 * Wait for all outstanding IOs to be flushed
	 * to disk before making further progress
	 */
	if (wquiesce) {
		/*
		 * mark the cloned volume as STALE.
		 * When zrepl got restarted/crashed before deleting
		 * the cloned volume, do not use this cloned volume,
		 * rather delete it.
		 */
		uzfs_zvol_store_kv_pair(zinfo->clone_zv, STALE, 1);

		/*
		 * set the quorum to 1 once rebuild is done. istgt will
		 * start considering it in the quorum decision.
		 */
		VERIFY0(uzfs_zinfo_set_quorum(zinfo, 1));

		mutex_enter(&zinfo->main_zv->rebuild_mtx);
		/* Mark replica healthy now */
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_DONE);
		uzfs_zvol_set_status(zinfo->main_zv,
		    ZVOL_STATUS_HEALTHY);
		uzfs_update_ionum_interval(zinfo, 0);
		mutex_exit(&zinfo->main_zv->rebuild_mtx);

		/*
		 * Lets ask io_receiver thread to flush
		 * all outstanding IOs in taskq so that
		 * no one is referring the cloned volume
		 * and we can delete it safely.
		 */
		zinfo->quiesce_done = 0;
		zinfo->quiesce_requested = 1;
		quiesce_wait(zinfo);

		/* This is to make sure that above kv is synced */
		txg_wait_synced(spa_get_dsl(zinfo->main_zv->zv_spa), 0);
	}

	kmem_free(arg, sizeof (rebuild_thread_arg_t));
	if (zio_cmd != NULL)
		zio_cmd_free(&zio_cmd);
	if (sfd != -1) {
		shutdown(sfd, SHUT_RDWR);
		close(sfd);
	}

#ifdef	DEBUG
	if (inject_error.delay.rebuild_complete == 1)
		sleep(10);
#endif

	if (wquiesce) {
		if (uzfs_zinfo_destroy_internal_clone(zinfo)) {
			mutex_enter(&zinfo->main_zv->rebuild_mtx);
			zinfo->main_zv->rebuild_info.stale_clone_exist++;
			mutex_exit(&zinfo->main_zv->rebuild_mtx);
		} else {
			zinfo->main_zv->rebuild_info.stale_clone_exist = 0;
		}
	}

	/* Parent thread have taken refcount, drop it now */
	uzfs_zinfo_drop_refcnt(zinfo);
	zk_thread_exit();
}

#define	STORE_LAST_COMMITTED_HEALTHY_IO_NO	\
    uzfs_zinfo_store_last_committed_healthy_io_no

#define	STORE_LAST_COMMITTED_DEGRADED_IO_NO	\
    uzfs_zinfo_store_last_committed_degraded_io_no

void
uzfs_zvol_timer_thread(void)
{
	zvol_info_t *zinfo;
	time_t min_interval;
	time_t now, next_check;
	struct singly_node_list zvol_node_list, free_node_list;
	singly_node_list_t *n_zinfo, *t_zinfo;

	init_zrepl();
	prctl(PR_SET_NAME, "zvol_timer", 0, 0, 0);
	SLIST_INIT(&zvol_node_list);
	SLIST_INIT(&free_node_list);

	mutex_enter(&timer_mtx);
	while (1) {
		min_interval = 5;  // we check intervals at least every 5 sec

		mutex_enter(&zvol_list_mutex);
		SLIST_FOREACH(zinfo, &zvol_list, zinfo_next) {
			if (!SLIST_EMPTY(&free_node_list)) {
				n_zinfo = SLIST_FIRST(&free_node_list);
				SLIST_REMOVE_HEAD(&free_node_list, node_next);
			} else {
				n_zinfo = kmem_alloc(sizeof (*n_zinfo),
				    KM_SLEEP);
			}
			uzfs_zinfo_take_refcnt(zinfo);
			n_zinfo->node = (void *) zinfo;
			SLIST_INSERT_HEAD(&zvol_node_list, n_zinfo, node_next);
		}
		mutex_exit(&zvol_list_mutex);

		next_check = now = time(NULL);
		SLIST_FOREACH(n_zinfo, &zvol_node_list, node_next) {
			zinfo = (zvol_info_t *)n_zinfo->node;
			if (uzfs_zvol_get_status(zinfo->main_zv) ==
			    ZVOL_STATUS_HEALTHY &&
			    zinfo->main_zv->zv_objset) {
				next_check = zinfo->checkpointed_time +
				    zinfo->update_ionum_interval;
				if (next_check <= now) {
					LOG_DEBUG("Checkpointing ionum "
					    "%lu on %s",
					    zinfo->checkpointed_ionum,
					    zinfo->name);
					STORE_LAST_COMMITTED_HEALTHY_IO_NO(
					    zinfo, zinfo->checkpointed_ionum);
					zinfo->checkpointed_ionum =
					    zinfo->running_ionum;
					zinfo->checkpointed_time = now;
					next_check = now +
					    zinfo->update_ionum_interval;
				}

				if (ZVOL_HAS_STALE_CLONE(zinfo->main_zv)) {
					uzfs_zinfo_destroy_stale_clone(zinfo);
				}
			} else if (uzfs_zvol_get_status(zinfo->main_zv) ==
			    ZVOL_STATUS_DEGRADED &&
			    zinfo->main_zv->zv_objset) {
				next_check = zinfo->degraded_checkpointed_time
				    + DEGRADED_IO_UPDATE_INTERVAL;
				if (next_check <= now &&
				    zinfo->degraded_checkpointed_ionum <
				    zinfo->running_ionum) {
					zinfo->degraded_checkpointed_ionum =
					    zinfo->running_ionum;
					LOG_DEBUG("Checkpointing ionum "
					    "%lu on %s for degraded mode",
					    zinfo->degraded_checkpointed_ionum,
					    zinfo->name);
					STORE_LAST_COMMITTED_DEGRADED_IO_NO(
					    zinfo,
					    zinfo->degraded_checkpointed_ionum);
					zinfo->degraded_checkpointed_time =
					    now;
					next_check = now +
					    DEGRADED_IO_UPDATE_INTERVAL;
				}
			}

			if (next_check > now &&
			    (min_interval > next_check - now))
				min_interval = next_check - now;
		}

		(void) cv_timedwait(&timer_cv, &timer_mtx, ddi_get_lbolt() +
		    SEC_TO_TICK(min_interval));

		SLIST_FOREACH_SAFE(n_zinfo, &zvol_node_list,
		    node_next, t_zinfo) {
			SLIST_REMOVE(&zvol_node_list, n_zinfo,
			    singly_node_list_s, node_next);
			zinfo = (zvol_info_t *)n_zinfo->node;
			uzfs_zinfo_drop_refcnt(zinfo);
			SLIST_INSERT_HEAD(&free_node_list, n_zinfo, node_next);
		}
	}

	mutex_exit(&timer_mtx);
	mutex_destroy(&timer_mtx);
	cv_destroy(&timer_cv);

	SLIST_FOREACH_SAFE(n_zinfo, &free_node_list, node_next, t_zinfo) {
		SLIST_REMOVE(&free_node_list, n_zinfo, singly_node_list_s,
		    node_next);
		kmem_free(n_zinfo, sizeof (*n_zinfo));
	}
	zk_thread_exit();
}

/*
 * Update interval and wake up timer thread so that it can adjust to the new
 * value. If timeout is zero, then we just wake up the timer thread (used in
 * case when zvol state is changed to make timer thread aware of it).
 */
void
uzfs_update_ionum_interval(zvol_info_t *zinfo, uint32_t timeout)
{
	mutex_enter(&timer_mtx);
	if (zinfo->update_ionum_interval == timeout) {
		mutex_exit(&timer_mtx);
		return;
	}
	if (timeout != 0)
		zinfo->update_ionum_interval = timeout;
	cv_signal(&timer_cv);
	mutex_exit(&timer_mtx);
}

/*
 * This function finds cmds that need to be acked to its sender on a given fd,
 * and removes those commands from that list.
 */
void
remove_pending_cmds_to_ack(int fd, zvol_info_t *zinfo)
{
	zvol_io_cmd_t *zio_cmd, *zio_cmd_next;
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
	while (zio_cmd != NULL) {
		zio_cmd_next = STAILQ_NEXT(zio_cmd, cmd_link);
		if (zio_cmd->conn == fd) {
			STAILQ_REMOVE(&zinfo->complete_queue, zio_cmd,
			    zvol_io_cmd_s, cmd_link);
			zio_cmd_free(&zio_cmd);
		}
		zio_cmd = zio_cmd_next;
	}
	while ((zinfo->zio_cmd_in_ack != NULL) &&
	    (((zvol_io_cmd_t *)(zinfo->zio_cmd_in_ack))->conn == fd)) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		LOG_INFO("Waiting for IO to send off on vol %s", zinfo->name);
		sleep(1);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
}

/*
 * One thread per replica. Responsible for accepting
 * IO connections. This thread will accept a connection
 * and spawn a new thread for each new connection req.
 *
 * This accepts connections for rebuild operation from
 * another replica to help it in rebuilding missing data.
 *
 * Exits if any error in bind/listen/epoll_* APIs
 */
void
uzfs_zvol_io_conn_acceptor(void *arg)
{
	int			io_sfd, efd;
	intptr_t		new_fd;
	int			rebuild_fd;
	int			rc, i, n;
	uint32_t		flags;
#ifdef DEBUG
	char			*hbuf;
	char			*sbuf;
#endif
	kthread_t		*thrd_info;
	socklen_t		in_len;
	struct sockaddr		in_addr;
	struct epoll_event	event;
	struct epoll_event	*events = NULL;
	char port[10];
	conn_acceptors_t	*ca = (conn_acceptors_t *)arg;

	io_sfd = rebuild_fd = efd = -1;
	flags = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

	/* Create IO connection acceptor fd in non-blocking mode */
	snprintf(port, 8, "%d", io_server_port);
	io_sfd = create_and_bind(port, B_TRUE, B_FALSE);
	if (io_sfd == -1) {
		LOG_ERRNO("unable to bind to port %s", port);
		goto exit;
	}

	rc = listen(io_sfd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on IO FD in acceptor failed");
		goto exit;
	}
	LOG_DEBUG("listening on port %s for IO", port);

	snprintf(port, 8, "%d", rebuild_io_server_port);
	rebuild_fd = create_and_bind(port, B_TRUE, B_FALSE);
	if (rebuild_fd == -1) {
		LOG_ERRNO("unable to bind to port %s", port);
		goto exit;
	}

	rc = listen(rebuild_fd, SOMAXCONN);
	if (rc == -1) {
		LOG_ERRNO("listen on rebuild FD in acceptor failed");
		goto exit;
	}
	LOG_DEBUG("listening on port %s for rebuild IO", port);

	efd = epoll_create1(0);
	if (efd == -1) {
		LOG_ERRNO("epoll_create1 failed");
		goto exit;
	}

	event.data.fd = io_sfd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, io_sfd, &event);
	if (rc == -1) {
		LOG_ERRNO("epoll_ctl on IO FD failed");
		goto exit;
	}

	event.data.fd = rebuild_fd;
	event.events = flags;
	rc = epoll_ctl(efd, EPOLL_CTL_ADD, rebuild_fd, &event);
	if (rc == -1) {
		LOG_ERRNO("epoll_ctl on rebuild FD failed");
		goto exit;
	}

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof (event));

	prctl(PR_SET_NAME, "acceptor", 0, 0, 0);

	if (ca != NULL) {
		ca->io_fd = io_sfd;
		ca->rebuild_fd = rebuild_fd;
	}

	/* The event loop */
	while (1) {
		n = epoll_wait(efd, events, MAXEVENTS, -1);
		/*
		 * EINTR err can come when signal handler
		 * interrupt epoll_wait system call. It
		 * should be okay to continue in that case.
		 */
		if ((n < 0) && (errno == EINTR)) {
			continue;
		} else if (n < 0) {
			goto exit;
		}

		for (i = 0; i < n; i++) {
			/*
			 * An error has occured on this fd, or
			 * the socket is not ready for reading
			 * (why were we notified then?)
			 */
			if ((events[i].events & (~EPOLLIN)) != 0) {
				LOG_ERRNO("epoll failed for io acceptor");
				if (events[i].data.fd == io_sfd) {
					io_sfd = -1;
				} else {
					rebuild_fd = -1;
				}
				close(events[i].data.fd);
				/*
				 * TODO:We have choosen to exit
				 * instead of continuing here.
				 */
				goto exit;
			}
			/*
			 * We have a notification on the listening
			 * socket, which means one or more incoming
			 * connections.
			 */
			in_len = sizeof (in_addr);
			new_fd = accept(events[i].data.fd, &in_addr, &in_len);
			if (new_fd == -1) {
				LOG_ERRNO("accept failed for io acceptor");
				continue;
			}
#ifdef DEBUG
			hbuf = kmem_alloc(NI_MAXHOST, KM_SLEEP);
			sbuf = kmem_alloc(NI_MAXSERV, KM_SLEEP);
			rc = getnameinfo(&in_addr, in_len, hbuf,
			    NI_MAXHOST, sbuf, NI_MAXSERV,
			    NI_NUMERICHOST | NI_NUMERICSERV);
			if (rc == 0) {
				LOG_DEBUG("Accepted connection from %s:%s",
				    hbuf, sbuf);
			}

			kmem_free(hbuf, NI_MAXHOST);
			kmem_free(sbuf, NI_MAXSERV);
#endif

			rc = set_socket_keepalive(new_fd);
			if (rc != 0)
				LOG_ERR("Failed to set keepalive on "
				    "accepted fd %d", new_fd);
			rc = 0;

			if (events[i].data.fd == io_sfd) {
				LOG_INFO("New data connection on fd %d",
				    new_fd);
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)io_receiver,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			} else {
				LOG_INFO("New rebuild connection on fd %d",
				    new_fd);
				thrd_info = zk_thread_create(NULL, 0,
				    (thread_func_t)rebuild_scanner,
				    (void *)new_fd, 0, NULL, TS_RUN, 0,
				    PTHREAD_CREATE_DETACHED);
			}
			VERIFY3P(thrd_info, !=, NULL);
		}
	}
exit:
	if (events != NULL)
		free(events);

	if (io_sfd != -1) {
		LOG_DEBUG("closing iofd %d", io_sfd);
		close(io_sfd);
	}

	if (rebuild_fd != -1) {
		LOG_DEBUG("closing rebuildfd %d", rebuild_fd);
		close(rebuild_fd);
	}

	if (efd != -1)
		close(efd);

	LOG_DEBUG("uzfs_zvol_io_conn_acceptor thread exiting");

	exit(1);
}

void
init_zrepl(void)
{
	mutex_init(&timer_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&timer_cv, NULL, CV_DEFAULT, NULL);
}

static int
uzfs_zvol_rebuild_scanner_callback(off_t offset, size_t len,
    blk_metadata_t *metadata, zvol_state_t *zv, void *args)
{
	zvol_io_hdr_t	hdr;
	zvol_io_cmd_t	*zio_cmd;
	zvol_rebuild_t  *warg;
	zvol_info_t	*zinfo;

	warg = (zvol_rebuild_t *)args;
	zinfo = warg->zinfo;

	hdr.version = REPLICA_VERSION;
	hdr.opcode = ZVOL_OPCODE_READ;
	hdr.io_seq = metadata->io_num;
	hdr.offset = offset;
	hdr.len = len;
	hdr.flags = ZVOL_OP_FLAG_REBUILD;
	hdr.status = ZVOL_OP_STATUS_OK;

	while (1) {
		if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
		    (!zinfo->is_io_ack_sender_created))
			return (-1);
		if (IS_REBUILD_HIT_MAX_CMD_LIMIT(zinfo))
			usleep(100);
		else
			break;
	}

	zinfo->rebuild_cmd_queued_cnt++;
	LOG_DEBUG("IO number for rebuild %ld", metadata->io_num);
	zio_cmd = zio_cmd_alloc(&hdr, warg->fd);
	/* Take refcount for uzfs_zvol_worker to work on it */
	uzfs_zinfo_take_refcnt(zinfo);
	zio_cmd->zinfo = zinfo;
	zinfo->rebuild_zv = zv;
	atomic_inc_64(&zinfo->dispatched_io_cnt);

	/*
	 * Any error in uzfs_zvol_worker will send FAILURE status to degraded
	 * replica. Degraded replica will take care of breaking the connection
	 */
	uzfs_zvol_worker(zio_cmd);
	zinfo->rebuild_zv = NULL;
	return (0);
}

void
uzfs_zvol_send_zio_cmd(zvol_info_t *zinfo, zvol_io_hdr_t *hdrp,
    zvol_op_code_t opcode, int fd, char *payload, uint64_t payload_size,
    uint64_t checkpointed_io_seq)
{

	zvol_io_cmd_t	*zio_cmd;
	bzero(hdrp, sizeof (*hdrp));
	hdrp->status = ZVOL_OP_STATUS_OK;
	hdrp->version = REPLICA_VERSION;
	hdrp->opcode = opcode;
	hdrp->checkpointed_io_seq = checkpointed_io_seq;
	hdrp->len = payload_size; // MAX_NAME_LEN + 1;
	zio_cmd = zio_cmd_alloc(hdrp, fd);
	if (payload_size != 0)
		bcopy(payload, zio_cmd->buf, payload_size);

	atomic_inc_64(&zinfo->dispatched_io_cnt);
	/* Take refcount for uzfs_zvol_worker to work on it */
	uzfs_zinfo_take_refcnt(zinfo);
	zio_cmd->zinfo = zinfo;
	uzfs_zvol_worker(zio_cmd);
}

/*
 * Creates internal snapshot on given zv using current time as part of snapname.
 * If snap already exists, waits and attempts to create again.
 * Returns zv of snapshot in snap_zv.
 */
int
uzfs_zvol_create_internal_snapshot(zvol_state_t *zv, zvol_state_t **snap_zv,
    uint64_t io_num)
{
	int ret = 0;
	char *snap_name;
	time_t now;
again:
	now = time(NULL);
	snap_name = kmem_asprintf("%s%llu.%llu", IO_DIFF_SNAPNAME, io_num, now);
	ret = get_snapshot_zv(zv, snap_name, snap_zv, B_TRUE, B_FALSE);
	if (ret == EEXIST) {
		strfree(snap_name);
		sleep(1);
		LOG_INFO("Waiting to create internal snapshot");
		goto again;
	}
	if (ret != 0)
		LOG_ERR("Failed to get info about %s@%s err(%d)",
		    zv->zv_name, snap_name, ret);
	strfree(snap_name);
	return (ret);
}

/*
 * Rebuild scanner function which after receiving
 * vol_name and IO number, will scan metadata and
 * read data and send across.
 */
void
uzfs_zvol_rebuild_scanner(void *arg)
{
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*snap_zv = NULL;
	zvol_io_hdr_t	hdr;
	int 		rc = 0;
	zvol_rebuild_t	warg;
	char 		*name;
	blk_metadata_t	metadata;
	uint64_t	rebuild_req_offset;
	uint64_t	rebuild_req_len;
	struct linger	lo = { 1, 0 };
	boolean_t	all_snap_done = B_FALSE;
	char		*payload = NULL;
	uint64_t	checkpointed_io_seq = 0;
	uint64_t	payload_size = 0;
	char		*snap_name;

	if ((rc = setsockopt(fd, SOL_SOCKET, SO_LINGER, &lo, sizeof (lo)))
	    != 0) {
		LOG_ERRNO("setsockopt failed for fd(%d)", fd);
		goto exit;
	}
read_socket:

#if DEBUG
	sleep(rand() % 3);
#endif
	if ((zinfo != NULL) &&
	    ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
	    (!zinfo->is_io_ack_sender_created)))
		goto exit;

	rc = uzfs_zvol_read_header(fd, &hdr);
	if ((rc != 0) ||
	    ((zinfo != NULL) &&
	    ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
	    (!zinfo->is_io_ack_sender_created))))
		goto exit;

	LOG_DEBUG("op_code=%d io_seq=%ld", hdr.opcode, hdr.io_seq);

	/* Handshake yet to happen */
	if ((hdr.opcode != ZVOL_OPCODE_HANDSHAKE) && (zinfo == NULL)) {
		LOG_DEBUG("Wrong opcode:%d, expecting handshake", hdr.opcode);
		rc = -1;
		goto exit;
	}
	switch (hdr.opcode) {
		case ZVOL_OPCODE_HANDSHAKE:
			name = kmem_alloc(hdr.len, KM_SLEEP);
			rc = uzfs_zvol_socket_read(fd, name, hdr.len);
			if (rc != 0) {
				LOG_ERR("Error reading zvol name from fd(%d)",
				    fd);
				kmem_free(name, hdr.len);
				goto exit;
			}

			/* Handshake already happened */
			if (zinfo != NULL) {
				LOG_ERR("Second handshake on %s connection for "
				    "zvol %s on fd(%d)",
				    zinfo->name, name, fd);
				kmem_free(name, hdr.len);
				rc = -1;
				goto exit;
			}

			zinfo = uzfs_zinfo_lookup(name);
			if (zinfo == NULL) {
				LOG_ERR("zvol %s not found for fd(%d)", name,
				    fd);
				kmem_free(name, hdr.len);
				rc = -1;
				goto exit;
			}

			LOG_INFO("Rebuild scanner started on zvol %s from "
			    "sock(%d)", name, fd);

			uzfs_zvol_append_to_fd_list(zinfo, fd);
			zinfo->rebuild_cmd_queued_cnt =
			    zinfo->rebuild_cmd_acked_cnt = 0;

			kmem_free(name, hdr.len);
			warg.zinfo = zinfo;
			warg.fd = fd;
			goto read_socket;

		case ZVOL_OPCODE_REBUILD_STEP:

			metadata.io_num = hdr.checkpointed_io_seq;
			rebuild_req_offset = hdr.offset;
			rebuild_req_len = hdr.len;

			LOG_INFO("Checkpointed IO_seq: %ld, "
			    "Rebuild Req offset: %ld, Rebuild Req length: %ld "
			    "for zvol(%s)",
			    metadata.io_num, rebuild_req_offset,
			    rebuild_req_len, zinfo->name);
#if DEBUG
			if (inject_error.delay.helping_replica_rebuild_step
			    == 1)
				sleep(5);
#endif
			if (snap_zv == NULL) {
				rc = uzfs_get_snap_zv_ionum(zinfo,
				    hdr.checkpointed_io_seq, &snap_zv);
				if (rc != 0) {
					LOG_ERR("Snap retrieve failed on zvol"
					    " %s, err(%d)", zinfo->name, rc);
					goto exit;
				}
#if DEBUG
				if (snap_zv != NULL)
					LOG_INFO("Rebuilding from zv:%s\n",
					    snap_zv->zv_name);
#endif
			}

			zvol_state_t *zv = zinfo->main_zv;
			if (snap_zv == NULL) {
			/*
			 * which means there is no user snapshot of given
			 * io_num, but, TODO: we need to make sure that there
			 * are no ongoing snapshots.
			 */
				if (all_snap_done == B_FALSE) {
					uzfs_zvol_send_zio_cmd(zinfo, &hdr,
					    ZVOL_OPCODE_REBUILD_ALL_SNAP_DONE,
					    fd, NULL, 0, 0);
					all_snap_done = B_TRUE;
				}
				if (ZINFO_IS_DEGRADED(zinfo))
					zv = zinfo->clone_zv;
				rc = uzfs_zvol_create_internal_snapshot(zv,
				    &snap_zv, metadata.io_num);
				if (rc != 0) {
					LOG_ERR("internal snap create failed %s"
					    " err(%d)", zinfo->name, rc);
					goto exit;
				}
			}

			rc = uzfs_get_io_diff(zv, &metadata,
			    snap_zv, uzfs_zvol_rebuild_scanner_callback,
			    rebuild_req_offset, rebuild_req_len, &warg);
			if (rc != 0) {
				LOG_ERR("Rebuild scanning failed on zvol %s ",
				    "err(%d)", zinfo->name, rc);
				goto exit;
			}

			uzfs_zvol_send_zio_cmd(zinfo, &hdr,
			    ZVOL_OPCODE_REBUILD_STEP_DONE,
			    fd, NULL, 0, 0);
			goto read_socket;

		case ZVOL_OPCODE_REBUILD_COMPLETE:
			/*
			 * Snapshot we were transferring was not
			 * internal snapshot, send snap_done opcode
			 */
			if (snap_zv != NULL && all_snap_done == B_FALSE) {
				rc = uzfs_zvol_get_last_committed_io_no(snap_zv,
				    HEALTHY_IO_SEQNUM, &checkpointed_io_seq);
				if (rc != 0) {
					LOG_ERR("Unable to get checkpointed num"
					    " on zvol:%s %d", zinfo->name, rc);
					goto exit;
				}

				payload_size = strlen(snap_zv->zv_name) + 1;
				payload = (char *)malloc(payload_size);
				strncpy(payload, snap_zv->zv_name,
				    payload_size);
				/* As DW replica to create snapshot */
				uzfs_zvol_send_zio_cmd(zinfo, &hdr,
				    ZVOL_OPCODE_REBUILD_SNAP_DONE,
				    fd, payload, payload_size,
				    checkpointed_io_seq + 1);
				free(payload);
				/* Close snapshot dataset */
				LOG_INFO("closing snap %s", snap_zv->zv_name);
				uzfs_close_dataset(snap_zv);
				snap_zv = NULL;
				goto read_socket;
			} else {
				if (snap_zv != NULL) {
					snap_name = kmem_asprintf("%s",
					    snap_zv->zv_name);
					LOG_INFO("closing snap %s", snap_name);
					uzfs_close_dataset(snap_zv);
#if DEBUG
					if (inject_error.delay.
					    helping_replica_rebuild_complete
					    == 1)
					sleep(10);
#endif
					rc = dsl_destroy_snapshot(snap_name,
					    B_FALSE);
					if (rc != 0)
						LOG_ERR("snap destroy failed %s"
						    " err(%d)", snap_name, rc);
					strfree(snap_name);
				}
				snap_zv = NULL;
				LOG_INFO("Rebuild process is over on zvol %s",
				    zinfo->name);
				goto exit;
			}

		default:
			LOG_ERR("Wrong opcode: %d during rebuild on sock(%d)",
			    hdr.opcode, fd);
			goto exit;
	}

exit:
	if (snap_zv != NULL && all_snap_done == B_FALSE) {
		LOG_INFO("closing snap on conn break %s", snap_zv->zv_name);
		uzfs_close_dataset(snap_zv);
		snap_zv = NULL;
	} else {
		if (snap_zv != NULL) {
			snap_name = kmem_asprintf("%s", snap_zv->zv_name);
			LOG_INFO("closing snap on conn break %s", snap_name);
			uzfs_close_dataset(snap_zv);
#if DEBUG
			if (inject_error.delay.helping_replica_rebuild_complete
			    == 1)
				sleep(10);
#endif
			rc = dsl_destroy_snapshot(snap_name, B_FALSE);
			if (rc != 0)
				LOG_ERR("snap destroy failed %s err: %d",
				    snap_name, rc);
			strfree(snap_name);
		}
		snap_zv = NULL;
	}

	if (zinfo != NULL) {
		LOG_INFO("Closing rebuild connection for zvol %s from sock(%d)",
		    zinfo->name, fd);
		remove_pending_cmds_to_ack(fd, zinfo);
		uzfs_zvol_remove_from_fd_list(zinfo, fd);

		uzfs_zinfo_drop_refcnt(zinfo);
	} else {
		LOG_INFO("Closing rebuild connection on sock(%d)", fd);
	}

	shutdown(fd, SHUT_RDWR);
	close(fd);
	zk_thread_exit();
}

/*
 * (Re)Initializes zv's state variables.
 * This fn need to be called to use zv across network disconnections.
 * Lock protection and life of zv need to be managed by caller
 */
static void
reinitialize_zv_state(zvol_state_t *zv)
{
	if (zv == NULL)
		return;

	uzfs_zvol_set_status(zv, ZVOL_STATUS_DEGRADED);
	uzfs_zvol_set_rebuild_status(zv, ZVOL_REBUILDING_INIT);
	zv->rebuild_info.stale_clone_exist = 0;
}

/*
 * This func takes care of sending potentially multiple read blocks each
 * prefixed by metainfo.
 */
static int
uzfs_send_reads(int fd, zvol_io_cmd_t *zio_cmd)
{
	zvol_io_hdr_t 	*hdr = &zio_cmd->hdr;
	struct zvol_io_rw_hdr read_hdr;
	metadata_desc_t	*md;
	size_t	rel_offset = 0;
	int	rc = 0;

	/* special case for missing metadata */
	if (zio_cmd->metadata_desc == NULL) {
		read_hdr.io_num = 0;
		/*
		 * read_hdr.len should be adjusted back
		 * to actual read request size now
		 */
		read_hdr.len = hdr->len -
		    sizeof (struct zvol_io_rw_hdr);
		rc = uzfs_zvol_socket_write(fd, (char *)&read_hdr,
		    sizeof (read_hdr));
		if (rc != 0)
			return (rc);
		/* Data that need to be sent is equal to read_hdr.len */
		rc = uzfs_zvol_socket_write(fd, zio_cmd->buf, read_hdr.len);
		return (rc);
	}

	/*
	 * TODO: Optimize performance by combining multiple writes to a single
	 * system call either by copying all data to larger buffer or using
	 * vector write.
	 */
	for (md = zio_cmd->metadata_desc; md != NULL; md = md->next) {
		read_hdr.io_num = md->metadata.io_num;
		read_hdr.len = md->len;
		rc = uzfs_zvol_socket_write(fd, (char *)&read_hdr,
		    sizeof (read_hdr));
		if (rc != 0)
			goto end;

		rc = uzfs_zvol_socket_write(fd,
		    (char *)zio_cmd->buf + rel_offset, md->len);
		if (rc != 0)
			goto end;
		rel_offset += md->len;
	}

end:
	FREE_METADATA_LIST(zio_cmd->metadata_desc);
	zio_cmd->metadata_desc = NULL;

	return (rc);
}

/*
 * One thread per LUN/vol. This thread works
 * on queue and it sends ack back to client on
 * a given fd.
 * There are two types of clients - one is iscsi target, and,
 * other is a replica which undergoes rebuild.
 * Need to exit from thread when there are network errors
 * on fd related to iscsi target.
 */
static void
uzfs_zvol_io_ack_sender(void *arg)
{
	int fd;
	int md_len;
	zvol_info_t		*zinfo;
	thread_args_t 		*thrd_arg;
	zvol_io_cmd_t 		*zio_cmd = NULL;
	uint64_t len, latency;

	thrd_arg = (thread_args_t *)arg;
	fd = thrd_arg->fd;
	zinfo = thrd_arg->zinfo;
	kmem_free(arg, sizeof (thread_args_t));

	prctl(PR_SET_NAME, "ack_sender", 0, 0, 0);

	LOG_INFO("Started ack sender for zvol %s fd: %d", zinfo->name, fd);

	while (1) {
		int rc = 0;
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
		zinfo->zio_cmd_in_ack = NULL;
		while (1) {
			if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE) ||
			    (zinfo->conn_closed == B_TRUE)) {
				(void) pthread_mutex_unlock(
				    &zinfo->zinfo_mutex);
				goto exit;
			}
			if (STAILQ_EMPTY(&zinfo->complete_queue)) {
				zinfo->io_ack_waiting = 1;
				pthread_cond_wait(&zinfo->io_ack_cond,
				    &zinfo->zinfo_mutex);
				zinfo->io_ack_waiting = 0;
			}
			else
				break;
		}

		zio_cmd = STAILQ_FIRST(&zinfo->complete_queue);
		STAILQ_REMOVE_HEAD(&zinfo->complete_queue, cmd_link);
		zinfo->zio_cmd_in_ack = zio_cmd;
		if (zio_cmd->hdr.flags & ZVOL_OP_FLAG_REBUILD)
			zinfo->rebuild_cmd_acked_cnt++;

		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

		LOG_DEBUG("ACK for op: %d, seq-id: %ld",
		    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq);

		/* account for space taken by metadata headers */
		if (zio_cmd->hdr.status == ZVOL_OP_STATUS_OK &&
		    zio_cmd->hdr.opcode == ZVOL_OPCODE_READ) {
			md_len = 0;
			for (metadata_desc_t *md = zio_cmd->metadata_desc;
			    md != NULL;
			    md = md->next) {
				md_len++;
			}
			/* we need at least one header even if no metadata */
			if (md_len == 0)
				md_len++;
			zio_cmd->hdr.len += (md_len *
			    sizeof (struct zvol_io_rw_hdr));
		}

		rc = uzfs_zvol_socket_write(zio_cmd->conn,
		    (char *)&zio_cmd->hdr, sizeof (zio_cmd->hdr));
		if (rc == -1)
			goto error_check;

		if (zio_cmd->hdr.opcode == ZVOL_OPCODE_REBUILD_SNAP_DONE) {
			rc = uzfs_zvol_socket_write(zio_cmd->conn,
			    zio_cmd->buf, zio_cmd->hdr.len);
error_check:
			if (rc == -1) {
				LOG_ERRNO("socket write err");
				zinfo->zio_cmd_in_ack = NULL;
				/*
				 * exit due to network errors on fd related
				 * to iscsi target
				 */
				if (zio_cmd->conn == fd) {
					zio_cmd_free(&zio_cmd);
					goto exit;
				}
				zio_cmd_free(&zio_cmd);
				continue;
			}
		}

		latency = 0;
		if (zio_cmd->hdr.opcode == ZVOL_OPCODE_READ) {
			if (zio_cmd->hdr.status == ZVOL_OP_STATUS_OK) {
				/* Send data read from disk */
				rc = uzfs_send_reads(zio_cmd->conn, zio_cmd);
				if (rc == -1) {
					zinfo->zio_cmd_in_ack = NULL;
					LOG_ERRNO("socket write err");
					if (zio_cmd->conn == fd) {
						zio_cmd_free(&zio_cmd);
						goto exit;
					}
				}
			}
			latency = gethrtime() - zio_cmd->io_start_time;
			atomic_inc_64(&zinfo->read_req_ack_cnt);
			atomic_add_64(&zinfo->read_byte, zio_cmd->hdr.len);
			atomic_add_64(&zinfo->read_latency, latency);

			len = zio_cmd->hdr.len;
			if (len < ZFS_HISTOGRAM_IO_SIZE) {
				zfs_histogram_add(zinfo->uzfs_rio_histogram,
				    len, len, latency);
			} else {
				zfs_histogram_add(zinfo->uzfs_rio_histogram,
				    ZFS_HISTOGRAM_IO_SIZE, len, latency);
			}
		} else {
			if (zio_cmd->hdr.opcode == ZVOL_OPCODE_WRITE) {
				latency = gethrtime() - zio_cmd->io_start_time;
				atomic_inc_64(&zinfo->write_req_ack_cnt);
				atomic_add_64(&zinfo->write_byte,
				    zio_cmd->hdr.len);
				atomic_add_64(&zinfo->write_latency, latency);

				len = zio_cmd->hdr.len;
				if (len < ZFS_HISTOGRAM_IO_SIZE) {
					zfs_histogram_add(zinfo->
					    uzfs_wio_histogram, len,
					    len, latency);
				} else {
					zfs_histogram_add(zinfo->
					    uzfs_wio_histogram,
					    ZFS_HISTOGRAM_IO_SIZE,
					    len, latency);
				}
			} else if (zio_cmd->hdr.opcode == ZVOL_OPCODE_SYNC) {
				atomic_inc_64(&zinfo->sync_req_ack_cnt);
				latency = (gethrtime() -
				    zio_cmd->io_start_time);
				atomic_add_64(&zinfo->sync_latency, latency);
			}
		}
		if ((latency >> 30) > IO_THRESHOLD_TIME)
			LOG_INFO("IO %d with seq: %lu took %luns",
			    zio_cmd->hdr.opcode, zio_cmd->hdr.io_seq, latency);
		zinfo->zio_cmd_in_ack = NULL;
		zio_cmd_free(&zio_cmd);
	}
exit:
	zinfo->zio_cmd_in_ack = NULL;
	shutdown(fd, SHUT_RDWR);

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	zinfo->is_io_ack_sender_created = 0;
	zinfo->conn_closed = B_FALSE;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	LOG_INFO("Data connection for zvol %s closed on fd: %d",
	    zinfo->name, fd);
	uzfs_zinfo_drop_refcnt(zinfo);

	zk_thread_exit();
}

/*
 * This function finds the appropriate state of zvol based on quorum and
 * open_data contents.
 * If quorum off, returns DEGRADED
 * else if internal snapshot might exists, returns DEGRADED
 * else if replication_factor is 1, returns HEALTHY
 * else returns DEGRADED
 */
static zvol_status_t
find_apt_zvol_status(zvol_info_t *zinfo, zvol_op_open_data_t *open_data)
{
	uint8_t quorum = uzfs_zinfo_get_quorum(zinfo);
	zvol_state_t *l_snap_zv = NULL;
	int ret = 0;

	if (quorum == 0) {
		LOG_INFO("Quorum is off, so, degraded mode with rep: %d",
		    open_data->replication_factor);
		return (ZVOL_STATUS_DEGRADED);
	}

	ret = get_snapshot_zv(zinfo->main_zv, REBUILD_SNAPSHOT_SNAPNAME,
	    &l_snap_zv, B_TRUE, B_TRUE);
	if (ret != ENOENT) {
		LOG_INFO("internal snapshot might exists.. err: %d "
		    "so, degraded mode with rep: %d", ret,
		    open_data->replication_factor);
		return (ZVOL_STATUS_DEGRADED);
	}

	if (open_data->replication_factor == 1) {
		LOG_INFO("Quorum is on, and rep factor 1");
		return (ZVOL_STATUS_HEALTHY);
	}

	return (ZVOL_STATUS_DEGRADED);
}

/*
 * Process open request on data connection, the first message.
 *
 * Return status meaning:
 *   != 0: OPEN failed, stop reading data from connection.
 *   == 0 && zinfopp == NULL: OPEN failed, recoverable error
 *   == 0 && zinfopp != NULL: OPEN succeeded, proceed with other commands
 */
static int
open_zvol(int fd, zvol_info_t **zinfopp)
{
	int		rc;
	zvol_io_hdr_t	hdr;
	zvol_op_open_data_t open_data;
	zvol_info_t	*zinfo = NULL;
	zvol_state_t	*zv = NULL;
	kthread_t	*thrd_info;
	thread_args_t 	*thrd_arg;
	int		rele_dataset_on_error = 0;
	zvol_status_t	status;

	/*
	 * If we don't know the version yet, be more careful when
	 * reading header
	 */
	if (uzfs_zvol_read_header(fd, &hdr) != 0) {
		LOG_ERR("error reading open header");
		return (-1);
	}
	if (hdr.opcode != ZVOL_OPCODE_OPEN) {
		LOG_ERR("zvol must be opened first");
		return (-1);
	}
	if (hdr.len != sizeof (open_data)) {
		LOG_ERR("Invalid payload length for open");
		return (-1);
	}
	rc = uzfs_zvol_socket_read(fd, (char *)&open_data, sizeof (open_data));
	if (rc != 0) {
		LOG_ERR("Payload read failed");
		return (-1);
	}

	open_data.volname[MAX_NAME_LEN - 1] = '\0';
	zinfo = uzfs_zinfo_lookup(open_data.volname);
	if (zinfo == NULL) {
		LOG_ERR("zvol %s not found", open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		goto open_reply;
	}
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	if (zinfo->state != ZVOL_INFO_STATE_ONLINE) {
		LOG_ERR("zvol %s is not online", open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	if (zinfo->is_io_ack_sender_created) {
		LOG_ERR("zvol %s ack sender already present",
		    open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	if (zinfo->is_io_receiver_created) {
		LOG_ERR("zvol %s io receiver already present",
		    open_data.volname);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}

	zv = zinfo->main_zv;
	ASSERT3P(zv, !=, NULL);

	ASSERT3P(uzfs_zinfo_get_status(zinfo), ==, ZVOL_STATUS_DEGRADED);
	ASSERT3P(zv->rebuild_info.zv_rebuild_status, ==, ZVOL_REBUILDING_INIT);

	if ((uzfs_zinfo_get_status(zinfo) != ZVOL_STATUS_DEGRADED) ||
	    ((zv->rebuild_info.zv_rebuild_status != ZVOL_REBUILDING_INIT) &&
	    (zv->rebuild_info.zv_rebuild_status != ZVOL_REBUILDING_FAILED))) {
		LOG_ERR("as status for %s is %d or rebuild status is %d",
		    open_data.volname, uzfs_zinfo_get_status(zinfo),
		    zv->rebuild_info.zv_rebuild_status);
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}
	// validate block size (only one bit is set in the number)
	if (open_data.tgt_block_size == 0 ||
	    (open_data.tgt_block_size & (open_data.tgt_block_size - 1)) != 0) {
		LOG_ERR("Invalid block size");
		hdr.status = ZVOL_OP_STATUS_FAILED;
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		goto open_reply;
	}

	/*
	 * Hold objset if this is the first query for the zvol. This can happen
	 * in case that the target creates data connection directly without
	 * getting the endpoint through mgmt connection first.
	 */
	rele_dataset_on_error = 0;
	if (zv->zv_objset == NULL) {
		if (uzfs_hold_dataset(zv) != 0) {
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			LOG_ERR("Failed to hold zvol during open");
			hdr.status = ZVOL_OP_STATUS_FAILED;
			goto open_reply;
		}
		rele_dataset_on_error = 1;
	}
	if (uzfs_update_metadata_granularity(zv,
	    open_data.tgt_block_size) != 0) {
		LOG_ERR("Failed to set granularity of metadata");
		goto error_ret;
	}

	status = find_apt_zvol_status(zinfo, &open_data);
	if (status == ZVOL_STATUS_HEALTHY) {
		ASSERT3P(zinfo->snapshot_zv, ==, NULL);
		ASSERT3P(zinfo->clone_zv, ==, NULL);
	} else {
		if (zinfo->snapshot_zv == NULL) {
			ASSERT3P(zinfo->clone_zv, ==, NULL);
			/* Create clone for rebuild */
			if (uzfs_zvol_get_or_create_internal_clone(
			    zinfo->main_zv, &zinfo->snapshot_zv,
			    &zinfo->clone_zv, NULL) != 0) {
				LOG_ERR("Failed to create clone for rebuild");
				goto error_ret;
			}
		}
		ASSERT3P(zinfo->clone_zv, !=, NULL);
		if (zinfo->clone_zv == NULL) {
			LOG_ERR("Failed to get clone");
error_ret:
			if (rele_dataset_on_error == 1)
				uzfs_rele_dataset(zv);
			hdr.status = ZVOL_OP_STATUS_FAILED;
			(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
			goto open_reply;
		}
	}
	/*
	 * TODO: Once we support multiple concurrent data connections for a
	 * single zvol, we should probably check that the timeout is the same
	 * for all data connections.
	 */
	uzfs_update_ionum_interval(zinfo, open_data.timeout);
	zinfo->timeout = open_data.timeout;
	*zinfopp = zinfo;

	zinfo->conn_closed = B_FALSE;
	zinfo->is_io_ack_sender_created = 1;
	zinfo->is_io_receiver_created = 1;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	(void) mutex_enter(&zinfo->main_zv->rebuild_mtx);
	if (status == ZVOL_STATUS_HEALTHY) {
		uzfs_zvol_set_rebuild_status(zinfo->main_zv,
		    ZVOL_REBUILDING_DONE);
		uzfs_zvol_set_status(zinfo->main_zv, status);
		uzfs_update_ionum_interval(zinfo, 0);
	}
	(void) mutex_exit(&zinfo->main_zv->rebuild_mtx);

	thrd_arg = kmem_alloc(sizeof (thread_args_t), KM_SLEEP);
	thrd_arg->fd = fd;
	thrd_arg->zinfo = zinfo;
	uzfs_zinfo_take_refcnt(zinfo);
	thrd_info = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_zvol_io_ack_sender, (void *)thrd_arg, 0, NULL,
	    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	VERIFY3P(thrd_info, !=, NULL);

	hdr.status = ZVOL_OP_STATUS_OK;

open_reply:
	hdr.len = 0;
	rc = uzfs_zvol_socket_write(fd, (char *)&hdr, sizeof (hdr));

	/*
	 * Reinitializing zv states during this error is taken care
	 * in open_zvol caller
	 */
	if (rc == -1)
		LOG_ERR("Failed to send reply for open request");
	if (hdr.status != ZVOL_OP_STATUS_OK) {
		ASSERT3P(*zinfopp, ==, NULL);
		if (zinfo != NULL)
			uzfs_zinfo_drop_refcnt(zinfo);
		return (-1);
	}
	return (rc);
}

/*
 * IO-Receiver would be per ZVOL, it would be
 * responsible for receiving IOs on given socket.
 */
void
uzfs_zvol_io_receiver(void *arg)
{
	int		rc;
	int		fd = (uintptr_t)arg;
	zvol_info_t	*zinfo = NULL;
	zvol_io_cmd_t	*zio_cmd;
	zvol_io_hdr_t	hdr;
	zvol_state_t	*snap_zv, *clone_zv;

	prctl(PR_SET_NAME, "io_receiver", 0, 0, 0);

	/* First command should be OPEN */
	while (zinfo == NULL) {
		if (open_zvol(fd, &zinfo) != 0) {
			if ((zinfo != NULL) &&
			    (zinfo->is_io_ack_sender_created))
				goto exit;
			shutdown(fd, SHUT_RDWR);
			goto thread_exit;
		}
	}

	zinfo->io_fd = fd;

	LOG_INFO("Data connection associated with zvol %s fd: %d",
	    zinfo->name, fd);

	while ((rc = uzfs_zvol_read_header(fd, &hdr)) == 0) {
		if ((zinfo->state == ZVOL_INFO_STATE_OFFLINE))
			break;

		if (hdr.opcode != ZVOL_OPCODE_WRITE &&
		    hdr.opcode != ZVOL_OPCODE_READ &&
		    hdr.opcode != ZVOL_OPCODE_SYNC) {
			LOG_ERR("Unexpected opcode %d", hdr.opcode);
			break;
		}

		if (((hdr.opcode == ZVOL_OPCODE_WRITE) ||
		    (hdr.opcode == ZVOL_OPCODE_READ)) && !hdr.len) {
			LOG_ERR("Zero Payload size for opcode %d", hdr.opcode);
			break;
		} else if ((hdr.opcode == ZVOL_OPCODE_SYNC) && hdr.len > 0) {
			LOG_ERR("Unexpected payload for opcode %d", hdr.opcode);
			break;
		}

		zio_cmd = zio_cmd_alloc(&hdr, fd);
		/* Read payload for commands which have it */
		if (hdr.opcode == ZVOL_OPCODE_WRITE) {
			rc = uzfs_zvol_socket_read(fd, zio_cmd->buf, hdr.len);
			if (rc != 0) {
				zio_cmd_free(&zio_cmd);
				break;
			}
		}

		if (zinfo->state == ZVOL_INFO_STATE_OFFLINE) {
			zio_cmd_free(&zio_cmd);
			break;
		}

		/* Take refcount for uzfs_zvol_worker to work on it */
		uzfs_zinfo_take_refcnt(zinfo);
		zio_cmd->zinfo = zinfo;

		/*
		 * Rebuild want to take consistent snapshot
		 * so it asked to flush all outstanding IOs
		 * before taking snapshot on rebuild_clone
		 */
		if (zinfo->quiesce_requested) {
			taskq_wait_outstanding(zinfo->uzfs_zvol_taskq, 0);
			zinfo->quiesce_requested = 0;
			zinfo->quiesce_done = 1;
		}

		atomic_inc_64(&zinfo->dispatched_io_cnt);

		taskq_dispatch(zinfo->uzfs_zvol_taskq, uzfs_zvol_worker,
		    zio_cmd, TQ_SLEEP);
	}
exit:
#if DEBUG
	if (inject_error.delay.io_receiver_exit == 1)
		sleep(5);
#endif
	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);

	if (zinfo->is_io_ack_sender_created)
		zinfo->conn_closed = B_TRUE;

	/*
	 * Send signal to ack sender so that it can free
	 * zio_cmd, close fd and exit.
	 */
	if (zinfo->io_ack_waiting) {
		rc = pthread_cond_signal(&zinfo->io_ack_cond);
	}
	/*
	 * wait for ack thread to exit to avoid races with new
	 * connections for the same zinfo
	 */
	while (zinfo->conn_closed || zinfo->is_io_ack_sender_created) {
		(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);
		LOG_INFO("Waiting for conn_closed(%d) and ack_sender (%d)"
		    "for fd(%d) to be false for %s", zinfo->conn_closed,
		    zinfo->is_io_ack_sender_created, fd, zinfo->name);
		sleep(1);
		(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	}
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	remove_pending_cmds_to_ack(fd, zinfo);

	shutdown_fds_related_to_zinfo(zinfo);

	zinfo->io_ack_waiting = 0;

	taskq_wait(zinfo->uzfs_zvol_taskq);
	reinitialize_zv_state(zinfo->main_zv);

	(void) pthread_mutex_lock(&zinfo->zinfo_mutex);
	snap_zv = zinfo->snapshot_zv;
	clone_zv = zinfo->clone_zv;
	zinfo->snapshot_zv = NULL;
	zinfo->clone_zv = NULL;
	(void) pthread_mutex_unlock(&zinfo->zinfo_mutex);

	(void) uzfs_zvol_release_internal_clone(zinfo->main_zv, snap_zv,
	    clone_zv);

	zinfo->quiesce_requested = 0;
	zinfo->quiesce_done = 1;
	zinfo->is_io_receiver_created = 0;
	zinfo->io_fd = -1;
	uzfs_zinfo_drop_refcnt(zinfo);
thread_exit:
	close(fd);
	LOG_INFO("Data connection closed on fd: %d", fd);
	zk_thread_exit();
}
