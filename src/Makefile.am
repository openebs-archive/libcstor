# Copyright © 2017-2019 The OpenEBS Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
