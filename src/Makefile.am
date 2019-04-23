ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libzrepl.la

DEFAULT_INCLUDES = ../include

EXTRA_DIST = \
			 data_conn.c \
			 libuzfs_handle.c \
			 libuzfs_server.c \
			 mgmt_conn.c \
			 rte_ring.c \
			 uzfs_io.c \
			 uzfs_mgmt.c \
			 uzfs_rebuilding.c \
			 uzfs_zap.c \
			 vdev_disk_aio.c \
			 zrepl_mgmt.c

nodist_libzrepl_la_SOURCES = $(EXTRA_DIST)

libzrepl_la_LIBADD =

libzrepl_la_LDFLAGS = -version-info 2:0:0
