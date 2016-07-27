#!/usr/bin/env bash

# Use directory of current script as the build directory and working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
ANDROID_BUILD_DIR="$(pwd)"

# Get access to android_build functions and variables
source ${ANDROID_BUILD_DIR}/android_build_helper.sh

# Choose a C++ standard library implementation from the ndk
ANDROID_BUILD_CXXSTL="gnustl_shared_49"

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

if [ -z $CURVE ]; then
    CURVE="--disable-curve"
    VERIFY="libzmq.so"
elif [ $CURVE == "libsodium" ]; then
    CURVE="--with-libsodium=yes"
    VERIFY="libzmq.so libsodium.so"
    ##
    # Build libsodium from latest master branch

    (android_build_verify_so "libsodium.so" &> /dev/null) || {
        rm -rf "${cache}/libsodium"
        (cd "${cache}" && git clone -b stable --depth 1 git://github.com/jedisct1/libsodium.git) || exit 1
        (cd "${cache}/libsodium" && ./autogen.sh \
            && ./configure --quiet "${ANDROID_BUILD_OPTS[@]}" --disable-soname-versions \
            && make -j 4 \
            && make install) || exit 1
    }
elif [ $CURVE == "tweetnacl" ]; then
    # Default
    CURVE=""
    VERIFY="libzmq.so"
fi

##
# Build libzmq from local source

LIBTOOL_EXTRA_LDFLAGS='-avoid-version'

(android_build_verify_so ${VERIFY} &> /dev/null) || {
    rm -rf "${cache}/libzmq"
    (cp -r ../.. "${cache}/libzmq" && cd "${cache}/libzmq" && make clean)
    
    (cd "${cache}/libzmq" && ./autogen.sh \
        && ./configure --quiet "${ANDROID_BUILD_OPTS[@]}" ${CURVE} --without-docs \
        && make -j 4 \
        && make install) || exit 1
}

##
# Verify shared libraries in prefix

android_build_verify_so ${VERIFY}
echo "libzmq android build succeeded"
