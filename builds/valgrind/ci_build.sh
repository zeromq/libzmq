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
CONFIG_OPTS+=("--enable-valgrind")

if [ -z $CURVE ]; then
    CONFIG_OPTS+=("--disable-curve")
elif [ $CURVE == "libsodium" ]; then
    CONFIG_OPTS+=("--with-libsodium=yes")

    if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
            (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
        git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
        ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make check; make install)
    fi
fi

# Build, check, and install from local source
( cd ../..; ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make -j5 && make VERBOSE=1 check-valgrind-memcheck) || exit 1
