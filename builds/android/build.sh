#!/usr/bin/env bash

set -e

function usage {
    echo "LIBZMQ (${BUILD_ARCH}) - Usage ./build.sh [ arm | arm64 | x86 | x86_64 ]"
}

# Use directory of current script as the build directory and working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
ANDROID_BUILD_DIR="${ANDROID_BUILD_DIR:-`pwd`}"

# Get access to android_build functions and variables
source ./android_build_helper.sh

# Choose a C++ standard library implementation from the ndk
export ANDROID_BUILD_CXXSTL="gnustl_shared_49"

# Additional flags for LIBTOOL, for LIBZMQ and other dependencies.
export LIBTOOL_EXTRA_LDFLAGS='-avoid-version'

BUILD_ARCH=$1
if [ -z $BUILD_ARCH ]; then
    usage
    exit 1
fi

platform="$(uname | tr '[:upper:]' '[:lower:]')"
case "${platform}" in
  linux*)  export HOST_PLATFORM=linux-x86_64 ;;
  darwin*) export HOST_PLATFORM=darwin-x86_64 ;;
  *)       echo "LIBZMQ (${BUILD_ARCH}) - Unsupported platform ('${platform}')" ; exit 1 ;;
esac

# Set default values used in ci builds
export NDK_VERSION=${NDK_VERSION:-android-ndk-r25}
# With NDK r22b, the minimum SDK version range is [16, 31].
# Since NDK r24, the minimum SDK version range is [19, 31].
# SDK version 21 is the minimum version for 64-bit builds.
export MIN_SDK_VERSION=${MIN_SDK_VERSION:-21}

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_set_env $BUILD_ARCH
android_build_env
android_build_opts

# Use a temporary build directory
cache="/tmp/android_build/${TOOLCHAIN_ARCH}"
rm -rf "${cache}"
mkdir -p "${cache}"

# Check for environment variable to clear the prefix and do a clean build
if [[ $ANDROID_BUILD_CLEAN ]]; then
    echo "LIBZMQ (${BUILD_ARCH}) - Doing a clean build (removing previous build and dependencies)..."
    rm -rf "${ANDROID_BUILD_PREFIX}"/*
fi

VERIFY=("libzmq.so")
if [ -z $CURVE ]; then
    CURVE="--disable-curve"
elif [ $CURVE == "libsodium" ]; then
    CURVE="--with-libsodium=yes"
    VERIFY+=("libsodium.so")
    ##
    # Build libsodium from latest master branch

    (android_build_verify_so "libsodium.so" &> /dev/null) || {
        rm -rf "${cache}/libsodium"
        (cd "${cache}" && git clone -b stable --depth 1 https://github.com/jedisct1/libsodium.git) || exit 1
        (
            CONFIG_OPTS=()
            CONFIG_OPTS+=("--quiet")
            CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
	    CONFIG_OPTS+=("--disable-soname-versions")

            cd "${cache}/libsodium" \
            && ./autogen.sh \
            && android_show_configure_opts "LIBSODIUM" "${CONFIG_OPTS[@]}" \
            && ./configure "${CONFIG_OPTS[@]}" \
            && make -j 4 \
            && make install
        ) || exit 1
    }
elif [ $CURVE == "tweetnacl" ]; then
    # Default
    CURVE=""
fi

##
# Build libzmq from local source

(android_build_verify_so "${VERIFY[@]}" &> /dev/null) || {
    rm -rf "${cache}/libzmq"
    (cp -r ../.. "${cache}/libzmq" && cd "${cache}/libzmq" && ( make clean || : ))

    (
        CONFIG_OPTS=()
        CONFIG_OPTS+=("--quiet")
        CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
        CONFIG_OPTS+=("${CURVE}")
        CONFIG_OPTS+=("--without-docs")
	
        cd "${cache}/libzmq" \
        && ./autogen.sh \
        && android_show_configure_opts "LIBZMQ" "${CONFIG_OPTS[@]}" \
        && ./configure "${CONFIG_OPTS[@]}" \
        && make -j 4 \
        && make install
    ) || exit 1
}

##
# Fetch the STL as well.

cp "${ANDROID_STL_ROOT}/${ANDROID_STL}" "${ANDROID_BUILD_PREFIX}/lib/."

##
# Verify shared libraries in prefix

android_build_verify_so "${VERIFY[@]}" "${ANDROID_STL}"
echo "LIBZMQ (${BUILD_ARCH}) - Android build successful"
