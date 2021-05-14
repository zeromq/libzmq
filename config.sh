#!/usr/bin/env bash

function set_config_opts() {
    CONFIG_OPTS=()
    CONFIG_OPTS+=("CFLAGS=-g")
    CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
    CONFIG_OPTS+=("CXXFLAGS=-g")
    CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
    CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")
    CONFIG_OPTS+=("--prefix=${BUILD_PREFIX}")
    CHECK="distcheck"

    if [ -n "$ADDRESS_SANITIZER" ] && [ "$ADDRESS_SANITIZER" = "enabled" ]; then
        CONFIG_OPTS+=("--enable-address-sanitizer=yes")
        # distcheck does an out-of-tree build, and the fuzzer tests use a hard-coded relative path for simplicity
        CHECK="check"
        git clone --depth 1 https://github.com/zeromq/libzmq-fuzz-corpora.git tests/libzmq-fuzz-corpora
    fi

    if [ "$USE_NSS" = "yes" ]; then
        CONFIG_OPTS+=("--with-nss")
    fi

    if [ -z "$CURVE" ]; then
        CONFIG_OPTS+=("--disable-curve")
    elif [ "$CURVE" = "libsodium" ]; then
        CONFIG_OPTS+=("--with-libsodium=yes")

        if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
                (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
            git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
            ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make install)
        fi
    fi

    if [ -n "$GSSAPI" ] && [ "$GSSAPI" = "enabled" ]; then
        CONFIG_OPTS+=("--with-libgssapi_krb5=yes")
    fi

    if [ -n "$PGM" ] && [ "$PGM" = "enabled" ]; then
        CONFIG_OPTS+=("--with-pgm=yes")
    fi

    if [ -n "$NORM" ] && [ "$NORM" = "enabled" ]; then
        CONFIG_OPTS+=("--with-norm=yes")
    fi

    if [ -n "$TIPC" ] && [ "$TIPC" = "enabled" ]; then
        sudo modprobe tipc
    fi

    if [ -n "$POLLER" ]; then
        CONFIG_OPTS+=("--with-poller=${POLLER}")
    fi

    if [ -n "$TLS" ] && [ "$TLS" = "enabled" ]; then
        CONFIG_OPTS+=("--with-tls=yes")
    fi

    if [ -z "$DRAFT" ] || [ "$DRAFT" = "disabled" ]; then
        CONFIG_OPTS+=("--enable-drafts=no")
    elif [ "$DRAFT" = "enabled" ]; then
        CONFIG_OPTS+=("--enable-drafts=yes")
    fi

    if [ -n "$FORCE_98" ] && [ "$FORCE_98" = "enabled" ]; then
        CONFIG_OPTS+=("--enable-force-CXX98-compat=yes")
    fi

    if [ -n "$VMCI" ] && [ "$VMCI" = "enabled" ]; then
        CONFIG_OPTS+=("--with-vmci=$PWD/vmci")
        # VMWare headeers are not ISO C++ compliant
        CONFIG_OPTS+=("--disable-pedantic")
        git clone --depth 1 https://github.com/vmware/open-vm-tools.git
        mkdir -p vmci
        # Linux headers are redefined, so we can't just add -I to the whole dir
        cp open-vm-tools/open-vm-tools/lib/include/vmci_* vmci/
    fi
}
