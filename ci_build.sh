#!/usr/bin/env bash

set -x
set -e

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
        make VERBOSE=1 distcheck
    ) || exit 1
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
