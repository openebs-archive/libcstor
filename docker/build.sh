#!/bin/bash

# Copyright 2020 The OpenEBS Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# enable gtest for builds
cd /usr/src/gtest && \
    cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt && \
    make && \
    cp *.so /usr/lib && \
    cd /libcstor

# clone cstor repo for required library files
git clone https://github.com/openebs/cstor.git && \ 
    cd cstor && \
    git checkout develop && \
    cd .. 

# build libcstor 
sh autogen.sh && \
    ./configure --with-zfs-headers=$PWD/cstor/include --with-spl-headers=$PWD/cstor/lib/libspl/include  && \
    make -j4 && \
    make install && \
    ldconfig

# build cstor
cd cstor && \
    sh autogen.sh && \
    ./configure --enable-uzfs=yes --with-config=user --with-jemalloc --with-libcstor=$PWD/../include && \
    make clean && \
    make -j4 && \
    cd /libcstor

# build zrepl
cd cmd/zrepl && \
    make clean && \
    make && \
    cd /libcstor

# copy all the build files
mkdir -p ./docker/zfs/bin ./docker/zfs/lib
cp cmd/zrepl/.libs/zrepl cstor/cmd/zpool/.libs/zpool cstor/cmd/zfs/.libs/zfs cstor/cmd/zstreamdump/.libs/zstreamdump ./docker/zfs/bin
cp cstor/lib/libzpool/.libs/*.so* cstor/lib/libuutil/.libs/*.so* cstor/lib/libnvpair/.libs/*.so* cstor/lib/libzfs/.libs/*.so* cstor/lib/libzfs_core/.libs/*.so* src/.libs/*.so* ./docker/zfs/lib
