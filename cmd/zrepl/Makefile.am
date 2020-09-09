# Copyright © 2020 The OpenEBS Authors
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

# -Wnoformat-truncation to get rid of compiler warning for unchecked
#  truncating snprintfs on gcc 7.1.1.
AM_CFLAGS = $(FRAME_LARGER_THAN)
# Dynamic symbol table is needed for printing symbol names in stack trace
AM_LDFLAGS = -rdynamic

AM_CPPFLAGS  = -D_GNU_SOURCE -D__EXTENSIONS__ -D_REENTRANT
AM_CPPFLAGS += -D_POSIX_PTHREAD_SEMANTICS -D_FILE_OFFSET_BITS=64
AM_CPPFLAGS += -D_LARGEFILE64_SOURCE -DHAVE_LARGE_STACKS=1
AM_CPPFLAGS += -DTEXT_DOMAIN=\"zfs-linux-user\"
AM_CPPFLAGS += -DLIBEXECDIR=\"$(libexecdir)\"
AM_CPPFLAGS += -DRUNSTATEDIR=\"$(runstatedir)\"
AM_CPPFLAGS += -DSBINDIR=\"$(sbindir)\"
AM_CPPFLAGS += -DSYSCONFDIR=\"$(sysconfdir)\"
AM_CPPFLAGS += $(CODE_COVERAGE_CPPFLAGS) $(UZFS_CFLAGS)

DEFAULT_INCLUDES = \
	-I$(top_srcdir)/include	\
    ${ZFS_SRC}	\
    ${SPL_SRC}

sbin_PROGRAMS = zrepl

zrepl_SOURCES = \
	zrepl.c

zrepl_LDADD = \
     $(zfssrc)/../lib/libnvpair/libnvpair.la \
     $(zfssrc)/../lib/libuutil/libuutil.la \
     $(zfssrc)/../lib/libzpool/libzpool.la \
     $(zfssrc)/../lib/libzfs/libzfs.la \
     $(zfssrc)/../lib/libzfs_core/libzfs_core.la

zrepl_LDADD += -lcstor -ludev -luuid -lz
