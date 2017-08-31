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
CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")
CONFIG_OPTS+=("--enable-code-coverage")

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

pip install --user cpp-coveralls

# Build, check, and install from local source
( cd ../..; ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make VERBOSE=1 -j5 check && coveralls --exclude tests --exclude src/tweetnacl.c --exclude src/tweetnacl.h --build-root . --gcov-options '\-lp') || exit 1
