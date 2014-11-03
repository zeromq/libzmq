#!/usr/bin/env bash

# Get directory of current script
ANDROID_BUILD_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Get access to android_build functions and variables
source ${ANDROID_BUILD_DIR}/android_build_helper.sh

# Choose a C++ standard library implementation from the ndk
ANDROID_BUILD_CXXSTL="gnustl_shared_48"

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_env
android_build_opts

# Clear a temporary build directory
cache="/tmp/android_build/${TOOLCHAIN_NAME}"
rm -rf "${cache}"
mkdir -p "${cache}"


echo
echo "Building qt-android libsodium from latest release tarball..."
echo

wget "https://download.libsodium.org/libsodium/releases/LATEST.tar.gz" \
    -O "${cache}/libsodium.tar.gz"

(cd "${cache}" && mkdir libsodium \
    && tar -C libsodium -xf libsodium.tar.gz --strip=1 \
    && cd "libsodium" && ./autogen.sh \
    && ./configure "${ANDROID_BUILD_OPTS[@]}" --disable-soname-versions \
    && make \
    && make install) || exit 1

echo
echo "Building qt-android libzmq from local source..."
echo

cp -r ../.. "${cache}/libzmq"

(cd "${cache}/libzmq" && ./autogen.sh \
    && ./configure "${ANDROID_BUILD_OPTS[@]}" --with-libsodium=yes \
    && make \
    && make install) || exit 1

echo
echo "Verifying qt-android libsodium.so and libzmq.so libraries..."
echo

android_build_verify_so "libsodium.so"
android_build_verify_so "libzmq.so" "libsodium.so"

echo
echo "Completed qt-android build!"
echo
