#!/usr/bin/env bash

set -x

mkdir tmp
BUILD_PREFIX=$PWD/tmp

CONFIG_OPTS=()
CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")

CMAKE_OPTS=()
CMAKE_OPTS+=("-DCMAKE_INSTALL_PREFIX:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_PREFIX_PATH:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_LIBRARY_PATH:PATH=${BUILD_PREFIX}/lib")
CMAKE_OPTS+=("-DCMAKE_INCLUDE_PATH:PATH=${BUILD_PREFIX}/include")

if [ -z $CURVE ]; then
    CMAKE_OPTS+=("-DENABLE_CURVE=OFF")
elif [ $CURVE == "libsodium" ]; then
    CMAKE_OPTS+=("-DWITH_LIBSODIUM=ON")

    git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
    ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make install)
fi

# Build, check, and install from local source
( cd ../..; mkdir build_cmake && cd build_cmake && PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig cmake "${CMAKE_OPTS[@]}" .. && make all VERBOSE=1 && make install && make test ) || exit 1
