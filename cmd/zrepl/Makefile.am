# -Wnoformat-truncation to get rid of compiler warning for unchecked
#  truncating snprintfs on gcc 7.1.1.
AM_CFLAGS = $(FRAME_LARGER_THAN)
# Dynamic symbol table is needed for printing symbol names in stack trace
AM_LDFLAGS = -rdynamic

AM_CPPFLAGS  = -D_GNU_SOURCE

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

zrepl_LDADD += -lcstor
