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
