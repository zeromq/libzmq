#!/usr/bin/env bash

# Use directory of current script as the build directory and working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
ANDROID_BUILD_DIR="$(pwd)"

# Get access to android_build functions and variables
source ${ANDROID_BUILD_DIR}/android_build_helper.sh

# Choose a C++ standard library implementation from the ndk
ANDROID_BUILD_CXXSTL="gnustl_shared_48"

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_env
android_build_opts

# Use a temporary build directory
cache="/tmp/android_build/${TOOLCHAIN_NAME}"
rm -rf "${cache}"
mkdir -p "${cache}"

# Check for environment variable to clear the prefix and do a clean build
if [[ $ANDROID_BUILD_CLEAN ]]; then
    echo "Doing a clean build (removing previous build and depedencies)..."
    rm -rf "${ANDROID_BUILD_PREFIX}"/*
fi

##
# Build libsodium from latest master branch

(android_build_verify_so "libsodium.so" &> /dev/null) || {
    rm -rf "${cache}/libsodium"
    (cd "${cache}" && git clone git://github.com/jedisct1/libsodium.git) || exit 1
    (cd "${cache}/libsodium" && ./autogen.sh \
        && ./configure "${ANDROID_BUILD_OPTS[@]}" --disable-soname-versions \
        && make \
        && make install) || exit 1
}

##
# Build libzmq from local source

LIBTOOL_EXTRA_LDFLAGS='-avoid-version'

(android_build_verify_so "libzmq.so" "libsodium.so" &> /dev/null) || {
    rm -rf "${cache}/libzmq"
    (cp -r ../.. "${cache}/libzmq" && cd "${cache}/libzmq" && make clean)
    
    (cd "${cache}/libzmq" && ./autogen.sh \
        && ./configure "${ANDROID_BUILD_OPTS[@]}" --with-libsodium=yes \
        && make \
        && make install) || exit 1
}

##
# Verify shared libraries in prefix

android_build_verify_so "libsodium.so"
android_build_verify_so "libzmq.so" "libsodium.so"
