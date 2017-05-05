#!/usr/bin/env bash

set -x
set -e

if [ $BUILD_TYPE == "default" ]; then
    mkdir tmp
    BUILD_PREFIX=$PWD/tmp

    CONFIG_OPTS=()
    CONFIG_OPTS+=("CFLAGS=-g")
    CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CXXFLAGS=-g")
    CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
    CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
    CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")

    if [ -n "$ADDRESS_SANITIZER" ] && [ "$ADDRESS_SANITIZER" == "enabled" ]; then
        CONFIG_OPTS+=("--enable-address-sanitizer=yes")
        CONFIG_OPTS+=("CXX=g++-6")
        CONFIG_OPTS+=("CC=gcc-6")
        # workaround for linker problem with ASAN options in GCC
        # http://stackoverflow.com/questions/37603238/fsanitize-not-using-gold-linker-in-gcc-6-1
        CONFIG_OPTS+=("LDFLAGS=-fuse-ld=gold")
    fi

    if [ -z $CURVE ]; then
        CONFIG_OPTS+=("--disable-curve")
    elif [ $CURVE == "libsodium" ]; then
        CONFIG_OPTS+=("--with-libsodium=yes")

        if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
                (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
            git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
            ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make install)
        fi
    fi

    if [ -z $DRAFT ] || [ $DRAFT == "disabled" ]; then
        CONFIG_OPTS+=("--enable-drafts=no")
    elif [ $DRAFT == "enabled" ]; then
        CONFIG_OPTS+=("--enable-drafts=yes")
    fi

    # Build and check this project
    (
        ./autogen.sh &&
        ./configure "${CONFIG_OPTS[@]}" &&
        export DISTCHECK_CONFIGURE_FLAGS="${CONFIG_OPTS[@]}" &&
        make VERBOSE=1 -j5 distcheck
    ) || exit 1
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
