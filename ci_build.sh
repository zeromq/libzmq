#!/usr/bin/env bash

set -x

if [ $BUILD_TYPE == "default" ]; then
    mkdir tmp
    BUILD_PREFIX=$PWD/tmp

    CONFIG_OPTS=()
    CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
    CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
    CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")

    #   Build required projects first

    #   libsodium
    git clone git://github.com/jedisct1/libsodium.git
    ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make check; make install)

    #   Build and check this project
    (
        ./autogen.sh &&
        ./configure "${CONFIG_OPTS[@]}" --with-libsodium=yes &&
        make &&
        ( if make check; then true; else cat test-suite.log; exit 1; fi ) &&
        make install
    ) || exit 1
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
