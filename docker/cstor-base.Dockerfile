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

FROM ubuntu:18.04 as build

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""

RUN mkdir -p cstor
COPY . libcstor/

# install all the build dependencies
RUN apt-get update -qq && \
    apt-get install --yes -qq gcc-6 g++-6 linux-headers-generic build-essential autoconf \
    libtool gawk alien fakeroot libaio-dev jq zlib1g-dev uuid-dev libattr1-dev libblkid-dev \
    parted lsscsi ksh attr acl nfs-kernel-server libgtest-dev cmake git \
    libselinux-dev libudev-dev libssl-dev libjson-c-dev lcov libjemalloc-dev gdb && \
    unlink /usr/bin/gcc && ln -s /usr/bin/gcc-6 /usr/bin/gcc && \
    unlink /usr/bin/g++ && ln -s /usr/bin/g++-6 /usr/bin/g++ 

# enable gtest for builds
RUN cd /usr/src/gtest && \
    cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt && \
    make && \
    cp *.so /usr/lib && \
    cd /

# clone cstor repo for required library files
RUN git clone https://github.com/openebs/cstor.git && \ 
    cd cstor && \
    git checkout develop && \
    cd .. 

# build libcstor 
RUN cd libcstor && \
    sh autogen.sh && \
    ./configure --with-zfs-headers=$PWD/../cstor/include --with-spl-headers=$PWD/../cstor/lib/libspl/include  && \
    make -j4 && \
    make install && \
    ldconfig

# build cstor
RUN cd ../cstor && \
    sh autogen.sh && \
    ./configure --enable-uzfs=yes --with-config=user --with-jemalloc --with-libcstor=$PWD/../libcstor/include && \
    make clean && \
    make -j4

# build zrepl
RUN cd ../libcstor/cmd/zrepl && \
    make clean && \
    make && \
    cd ../../

# copy all the build files
RUN cd libcstor && mkdir -p ./docker/zfs/bin ./docker/zfs/lib
RUN cd libcstor && cp cmd/zrepl/.libs/zrepl ../cstor/cmd/zpool/.libs/zpool ../cstor/cmd/zfs/.libs/zfs ../cstor/cmd/zstreamdump/.libs/zstreamdump ./docker/zfs/bin
RUN cd libcstor && cp ../cstor/lib/libzpool/.libs/*.so* ../cstor/lib/libuutil/.libs/*.so* ../cstor/lib/libnvpair/.libs/*.so* ../cstor/lib/libzfs/.libs/*.so* ../cstor/lib/libzfs_core/.libs/*.so* src/.libs/*.so* ./docker/zfs/lib

#Final
FROM ubuntu:bionic-20200219

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT=""

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \ 
    apt-get update && apt-get install -y \
    curl tcpdump dnsutils iputils-ping \
    libaio1 libaio-dev \
    libssl1.0.0 rsyslog net-tools gdb apt-utils \
    sed libjemalloc-dev

RUN if [ "$TARGETARCH" != "arm64" ]; then \
    apt-get install -y libkqueue-dev; \
    fi

RUN apt-get -y install apt-file && apt-file update

COPY --from=build libcstor/docker/zfs/bin/* /usr/local/bin/
COPY --from=build libcstor/docker/zfs/lib/* /usr/lib/

ARG DBUILD_DATE
ARG DBUILD_REPO_URL
ARG DBUILD_SITE_URL

LABEL org.label-schema.name="cstor"
LABEL org.label-schema.description="OpenEBS cStor"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$DBUILD_DATE
LABEL org.label-schema.vcs-url=$DBUILD_REPO_URL
LABEL org.label-schema.url=$DBUILD_SITE_URL

EXPOSE 7676
