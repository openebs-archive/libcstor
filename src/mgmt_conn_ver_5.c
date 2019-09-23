/*
 * Copyright © 2017-2019 The OpenEBS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <sys/types.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_objset.h>
#include <zrepl_mgmt.h>
#include <zrepl_prot.h>
#include <data_conn.h>
#include <uzfs_mgmt.h>

/*
 * uzfs_zvol_mgmt_get_handshake_info_ver_5 fills up the acknowledgement
 * for management connection for target having version <=5
 */
int
uzfs_zvol_mgmt_get_handshake_info_ver_5(zvol_io_hdr_t *in_hdr, const char *name,
    zvol_info_t *zinfo, zvol_io_hdr_t *out_hdr, mgmt_ack_ver_5_t *mgmt_ack)
{
	zvol_state_t	*zv = zinfo->main_zv;
	int error1, error2;
	bzero(mgmt_ack, sizeof (*mgmt_ack));
	if (uzfs_zvol_get_ip(mgmt_ack->ip, MAX_IP_LEN) == -1) {
		LOG_ERRNO("Unable to get IP");
		return (-1);
	}

	strlcpy(mgmt_ack->volname, name, sizeof (mgmt_ack->volname));
	mgmt_ack->port = (in_hdr->opcode == ZVOL_OPCODE_PREPARE_FOR_REBUILD) ?
	    REBUILD_IO_SERVER_PORT : IO_SERVER_PORT;
	mgmt_ack->pool_guid = spa_guid(zv->zv_spa);

	/*
	 * hold dataset during handshake if objset is NULL
	 * no critical section here as rebuild & handshake won't come at a time
	 */
	if (zv->zv_objset == NULL) {
		if (uzfs_hold_dataset(zv) != 0) {
			LOG_ERR("Failed to hold zvol %s", zinfo->name);
			return (-1);
		}
	}

	error1 = uzfs_zvol_get_last_committed_io_no(zv, HEALTHY_IO_SEQNUM,
	    &zinfo->checkpointed_ionum);
	error2 = uzfs_zvol_get_last_committed_io_no(zv, DEGRADED_IO_SEQNUM,
	    &zinfo->degraded_checkpointed_ionum);
	if (error1 != 0) {
		LOG_ERR("Failed to read io_seqnum %s, err1: %d err2: %d",
		    zinfo->name, error1, error2);
		return (-1);
	}

	/*
	 * Success condition for error2
	 * error2 can be 0 (or)
	 * error2 can be ENOENT
	 */
	if ((error2 != 0) && (error2 != ENOENT)) {
		LOG_ERR("Failed to read degraded_io %s, err1: %d err2: %d",
		    zinfo->name, error1, error2);
		return (-1);
	}

	if (error2 != 0) {
		LOG_ERR("Failed to read degraded_io %sd err: %d", zinfo->name,
		    error2);
		zinfo->degraded_checkpointed_ionum = 0;
	}

	/*
	 * We don't use fsid_guid because that one is not guaranteed
	 * to stay the same (it is changed in case of conflicts).
	 */
	mgmt_ack->zvol_guid = dsl_dataset_phys(
	    zv->zv_objset->os_dsl_dataset)->ds_guid;
	if (zinfo->zvol_guid == 0)
		zinfo->zvol_guid = mgmt_ack->zvol_guid;
	LOG_INFO("Volume:%s has zvol_guid:%lu", zinfo->name, zinfo->zvol_guid);

	bzero(out_hdr, sizeof (*out_hdr));
	out_hdr->version = in_hdr->version;
	out_hdr->opcode = in_hdr->opcode; // HANDSHAKE or PREPARE_FOR_REBUILD
	out_hdr->io_seq = in_hdr->io_seq;
	out_hdr->len = sizeof (*mgmt_ack);
	out_hdr->status = ZVOL_OP_STATUS_OK;

	zinfo->stored_healthy_ionum = zinfo->checkpointed_ionum;
	zinfo->running_ionum = zinfo->degraded_checkpointed_ionum;
	LOG_INFO("IO sequence number:%lu Degraded IO sequence number:%lu",
	    zinfo->checkpointed_ionum, zinfo->degraded_checkpointed_ionum);

	mgmt_ack->checkpointed_io_seq = zinfo->checkpointed_ionum;
	mgmt_ack->checkpointed_degraded_io_seq =
	    zinfo->degraded_checkpointed_ionum;
	mgmt_ack->quorum = uzfs_zinfo_get_quorum(zinfo);

	return (0);
}

/*
 * Sanitizes the START_REBUILD request payload.
 * Starts rebuild thread to every helping replica
 */
int
uzfs_zinfo_rebuild_start_threads_ver_5(mgmt_ack_ver_5_t *mack,
    zvol_info_t *zinfo, int rebuild_op_cnt)
{
	int 			io_sfd = -1;
	rebuild_thread_arg_t	*thrd_arg;
	kthread_t		*thrd_info;
	for (; rebuild_op_cnt > 0; rebuild_op_cnt--, mack++) {
		if (uzfs_zvol_name_compare(zinfo, mack->dw_volname) != 0) {
			LOG_ERR("zvol %s not matching with zinfo %s",
			    mack->dw_volname, zinfo->name);
ret_error:
			mutex_enter(&zinfo->main_zv->rebuild_mtx);

			/* Error happened, so set to REBUILD_ERRORED state */
			uzfs_zvol_set_rebuild_status(zinfo->main_zv,
			    ZVOL_REBUILDING_ERRORED);

			(zinfo->main_zv->rebuild_info.rebuild_failed_cnt) +=
			    rebuild_op_cnt;
			(zinfo->main_zv->rebuild_info.rebuild_done_cnt) +=
			    rebuild_op_cnt;

			/*
			 * If all the triggered rebuilds are done,
			 * mark state as REBUILD_FAILED
			 */
			if (zinfo->main_zv->rebuild_info.rebuild_cnt ==
			    zinfo->main_zv->rebuild_info.rebuild_done_cnt)
				uzfs_zvol_set_rebuild_status(zinfo->main_zv,
				    ZVOL_REBUILDING_FAILED);

			mutex_exit(&zinfo->main_zv->rebuild_mtx);
			return (-1);
		}

		io_sfd = create_and_bind("", B_FALSE, B_FALSE);
		if (io_sfd < 0) {
			/* Fail this rebuild process entirely */
			LOG_ERR("Rebuild IO socket create and bind"
			    " failed on zvol: %s", zinfo->name);
			goto ret_error;
		}

		LOG_INFO("[%s:%d] at %s:%u helping in rebuild",
		    mack->volname, io_sfd, mack->ip, mack->port);
		uzfs_zinfo_take_refcnt(zinfo);

		thrd_arg = kmem_alloc(sizeof (rebuild_thread_arg_t), KM_SLEEP);
		thrd_arg->zinfo = zinfo;
		thrd_arg->fd = io_sfd;
		thrd_arg->port = mack->port;
		strlcpy(thrd_arg->ip, mack->ip, MAX_IP_LEN);
		strlcpy(thrd_arg->zvol_name, mack->volname, MAXNAMELEN);
		thrd_info = zk_thread_create(NULL, 0,
		    dw_replica_fn, thrd_arg, 0, NULL, TS_RUN, 0,
		    PTHREAD_CREATE_DETACHED);
		VERIFY3P(thrd_info, !=, NULL);
	}

	return (0);
}