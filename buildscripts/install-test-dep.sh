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

if [ -z "${REPO_ORG}" ]; then
  echo "REPO_ORG variable not set. Required for fetching dependent build repositories"
  exit 1
else
  echo "Using repository organization: ${REPO_ORG}"
fi

if [ -z "${BRANCH}" ]; then
  echo "BRANCH variable not set. Required for checking out libcstor repository"
  exit 1
else
  echo "Using branch: ${BRANCH} for libcstor"
fi

#zrepl will make use of /var/tmp/sock directory to create a sock file.
mkdir -p /var/tmp/sock
pushd .
cd /usr/src/gtest || exit 1
sudo cmake CMakeLists.txt
sudo make -j4
sudo cp *.a /usr/lib
popd || exit 1
# save the current location to get back
pushd .
cd ..
# we need fio repo to build zfs replica fio engine
git clone https://github.com/axboe/fio
cd fio || exit 1
git checkout fio-3.9
./configure
make -j4
cd ..
git clone https://github.com/openebs/spl
cd spl || exit 1
git checkout spl-0.7.9
sh autogen.sh
./configure
make -j4
cd ..
# we need cstor headers
git clone https://github.com/${REPO_ORG}/cstor.git
cd cstor || exit 1
if [ "${BRANCH}" == "master" ]; then
  git checkout develop
else
  git checkout ${BRANCH} || git checkout develop
fi

git branch

# Return to libcstor code base
popd || exit 1
sh autogen.sh
./configure --enable-debug --with-zfs-headers=$PWD/../cstor/include --with-spl-headers=$PWD/../cstor/lib/libspl/include
make -j4
sudo make install
sudo ldconfig

# Return to cstor code
cd ..
cd cstor || exit 1
sh autogen.sh
./configure --with-config=user  --enable-debug --enable-uzfs=yes --with-jemalloc --with-fio=$PWD/../fio --with-libcstor=$PWD/../libcstor/include
make -j4;

# Return to libcstor code to complie zrepl which contains main process and to run lint checks
cd ..
cd libcstor || exit 1
make check-license
make -f ../cstor/Makefile cstyle CSTORDIR=$PWD/../cstor
# Go to zrepl directory to build zrepl related targets
cd cmd/zrepl || exit 1
make
cd ../../
# back to cstor for running further tests.
cd ..
cd cstor || exit 1
echo $PWD
