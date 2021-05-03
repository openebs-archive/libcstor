#!/bin/bash

sudo apt-get update -qq
sudo apt-get install --yes -qq gcc-6 g++-6
sudo apt-get install --yes -qq build-essential autoconf libtool gawk alien fakeroot libaio-dev jq

sudo apt-get install --yes -qq linux-headers-generic;
sudo apt-get install --yes -qq zlib1g-dev uuid-dev libattr1-dev libblkid-dev libselinux-dev libudev-dev libssl-dev libjson-c-dev
sudo apt-get install --yes -qq lcov libjemalloc-dev

sudo apt-get install --yes -qq parted lsscsi ksh attr acl nfs-kernel-server;

sudo apt-get install --yes -qq libgtest-dev cmake

sudo apt-get install git

# packages for debugging
sudo apt-get install gdb
# use gcc-6 by default
sudo unlink /usr/bin/gcc && sudo ln -s /usr/bin/gcc-6 /usr/bin/gcc
sudo unlink /usr/bin/g++ && sudo ln -s /usr/bin/g++-6 /usr/bin/g++
