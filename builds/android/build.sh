#!/usr/bin/env bash

function usage {
    echo "Usage ./build.sh [ arm | arm64 | x86 | x86_64 ]"
}

# Use directory of current script as the build directory and working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
ANDROID_BUILD_DIR="${ANDROID_BUILD_DIR:-`pwd`}"

# Get access to android_build functions and variables
source ./android_build_helper.sh

# Choose a C++ standard library implementation from the ndk
ANDROID_BUILD_CXXSTL="gnustl_shared_49"

BUILD_ARCH=$1

if [ -z $BUILD_ARCH ]; then
    usage
    exit 1
fi

case $(uname | tr '[:upper:]' '[:lower:]') in
  linux*)
    export HOST_PLATFORM=linux-x86_64
    ;;
  darwin*)
    export HOST_PLATFORM=darwin-x86_64
    ;;
  *)
    echo "Unsupported platform"
    exit 1
    ;;
esac

# Set default values used in ci builds

export NDK_VERSION=${NDK_VERSION:-android-ndk-r20}
# With NDK r20, the minimum SDK version range is [16, 29].
# SDK version 21 is the minimum version for 64-bit builds.
export MIN_SDK_VERSION=${MIN_SDK_VERSION:-21}

# Set variables for each architecture
HOST_ARM="arm-linux-androideabi"
HOST_ARM64="aarch64-linux-android"
HOST_X86="i686-linux-android"
HOST_X86_64="x86_64-linux-android"

COMP_ARM="armv7a-linux-androideabi${MIN_SDK_VERSION}"
COMP_ARM64="aarch64-linux-android${MIN_SDK_VERSION}"
COMP_X86="i686-linux-android${MIN_SDK_VERSION}"
COMP_X86_64="x86_64-linux-android${MIN_SDK_VERSION}"

CXXSTL_ARM="armeabi-v7a"
CXXSTL_ARM64="arm64-v8a"
CXXSTL_X86="x86"
CXXSTL_X86_64="x86_64"

ARCH_ARM="arm"
ARCH_ARM64="arm64"
ARCH_X86="x86"
ARCH_X86_64="x86_64"

if [ $BUILD_ARCH == "arm" ]; then
    android_build_arch $HOST_ARM $COMP_ARM $CXXSTL_ARM $ARCH_ARM
elif [ $BUILD_ARCH == "x86" ]; then
    android_build_arch $HOST_X86 $COMP_X86 $CXXSTL_X86 $ARCH_X86
elif [ $BUILD_ARCH == "arm64" ]; then
    android_build_arch $HOST_ARM64 $COMP_ARM64 $CXXSTL_ARM64 $ARCH_ARM64
elif [ $BUILD_ARCH == "x86_64" ]; then
    android_build_arch $HOST_X86_64 $COMP_X86_64 $CXXSTL_X86_64 $ARCH_X86_64
else
    usage
    exit 1
fi

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_env
android_build_opts

# Use a temporary build directory
cache="/tmp/android_build/${TOOLCHAIN_ARCH}"
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
