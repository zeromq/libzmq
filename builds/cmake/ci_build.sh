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

    if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
            (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
        git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
        ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make install)
    fi
fi

# Build, check, and install from local source
if [ "$DO_CLANG_FORMAT_CHECK" -eq "1" ] ; then
    if ! (cd ../..; mkdir build_cmake && cd build_cmake && PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig cmake "${CMAKE_OPTS[@]}" .. && make clang-format-check) ; then 
        make clang-format-diff
        exit 1
    fi
else
    ( cd ../..; mkdir build_cmake && cd build_cmake && PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig cmake "${CMAKE_OPTS[@]}" .. && make -j5 all VERBOSE=1 && make install && make -j5 test ) || exit 1
fi
