#!/usr/bin/env bash

set -x
set -e

cd ../../

mkdir tmp
BUILD_PREFIX=$PWD/tmp

CONFIG_OPTS=()
CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include -g -Og")
CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include -g -Og")
CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")
CONFIG_OPTS+=("--enable-drafts=no")

function print_abi_api_breakages() {
   echo "ABI breakages detected:"
   cat compat_reports/libzmq/${LATEST_VERSION}_to_HEAD/abi_affected.txt | c++filt
   echo "API breakages detected:"
   cat compat_reports/libzmq/${LATEST_VERSION}_to_HEAD/src_affected.txt | c++filt
   exit 1
}

./autogen.sh
./configure "${CONFIG_OPTS[@]}"
make VERBOSE=1 -j5
abi-dumper src/.libs/libzmq.so -o ${BUILD_PREFIX}/libzmq.head.dump -lver HEAD

git clone --depth 1 -b latest_release https://github.com/zeromq/libzmq.git latest_release
cd latest_release
LATEST_VERSION=$(git describe --abbrev=0 --tags)
./autogen.sh
./configure "${CONFIG_OPTS[@]}"
make VERBOSe=1 -j5
abi-dumper src/.libs/libzmq.so -o ${BUILD_PREFIX}/libzmq.latest.dump -lver ${LATEST_VERSION}

abi-compliance-checker -l libzmq -d1 ${BUILD_PREFIX}/libzmq.latest.dump -d2 ${BUILD_PREFIX}/libzmq.head.dump -list-affected || print_abi_api_breakages
