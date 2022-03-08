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

WORKDIR libcstor
COPY . .

# install all the build dependencies
RUN apt-get update -qq && \
    apt-get install --yes -qq gcc-6 g++-6 linux-headers-generic build-essential autoconf \
    libtool gawk alien fakeroot libaio-dev jq zlib1g-dev uuid-dev libattr1-dev libblkid-dev \
    parted lsscsi ksh attr acl nfs-kernel-server libgtest-dev cmake git \
    libselinux-dev libudev-dev libssl-dev libjson-c-dev lcov libjemalloc-dev gdb && \
    unlink /usr/bin/gcc && ln -s /usr/bin/gcc-6 /usr/bin/gcc && \
    unlink /usr/bin/g++ && ln -s /usr/bin/g++-6 /usr/bin/g++ 

ARG CSTOR_ORG
# build using script
RUN ./docker/build.sh

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

ARG DBUILD_DATE
ARG DBUILD_REPO_URL
ARG DBUILD_SITE_URL

LABEL org.label-schema.name="cstor"
LABEL org.label-schema.description="OpenEBS cStor"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$DBUILD_DATE
LABEL org.label-schema.vcs-url=$DBUILD_REPO_URL
LABEL org.label-schema.url=$DBUILD_SITE_URL

COPY --from=build libcstor/docker/zfs/bin/* /usr/local/bin/
COPY --from=build libcstor/docker/zfs/lib/* /usr/lib/

EXPOSE 7676
