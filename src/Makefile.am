ACLOCAL_AMFLAGS = -I m4

#Enable UZFS support
AM_CFLAGS=-D_UZFS

AM_CPPFLAGS=-D_GNU_SOURCE

lib_LTLIBRARIES = libcstor.la

DEFAULT_INCLUDES =	\
	-include ${top_builddir}/config.h	\
	-I../include	\
	${SPL_SRC} 	\
	${ZFS_SRC}

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
			 zrepl_mgmt.c	\
			 uzfs_test_mgmt.c \
			 uzfs_prop.c

nodist_libcstor_la_SOURCES = $(EXTRA_DIST)

libcstor_la_LIBADD = -laio -ldl -lm -ljson-c

libcstor_la_LDFLAGS = -version-info 2:0:0
