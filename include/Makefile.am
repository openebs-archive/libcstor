SUBDIRS = sys generic arch/arm arch/x86 arch/ppc

HEADER_H = \
	$(top_srcdir)/include/data_conn.h	\
	$(top_srcdir)/include/gtest_utils.h	\
	$(top_srcdir)/include/libuzfs.h	\
	$(top_srcdir)/include/mgmt_conn.h	\
	$(top_srcdir)/include/rte_common.h	\
	$(top_srcdir)/include/rte_memory.h	\
	$(top_srcdir)/include/rte_ring.h	\
	$(top_srcdir)/include/uzfs_io.h	\
	$(top_srcdir)/include/uzfs_mgmt.h	\
	$(top_srcdir)/include/uzfs_rebuilding.h	\
	$(top_srcdir)/include/uzfs_test.h	\
	$(top_srcdir)/include/uzfs_zap.h	\
	$(top_srcdir)/include/zrepl_mgmt.h	\
	$(top_srcdir)/include/zrepl_prot.h	\
	$(top_srcdir)/include/uzfs_prop.h

EXTRA_DIST = $(HEADER_H)

libcstordir = $(includedir)/libcstor
libcstor_HEADERS = $(HEADER_H)
