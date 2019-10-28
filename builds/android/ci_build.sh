#!/usr/bin/env bash

NDK_VERSION=android-ndk-r20
NDK_ABI_VERSION=4.9

if [ $TRAVIS_OS_NAME == "linux" ]
then
    HOST_PLATFORM=linux-x86_64
elif [ $TRAVIS_OS_NAME == "osx" ]
then
    HOST_PLATFORM=darwin-x86_64
else
    echo "Unsupported platform $TRAVIS_OS_NAME"
    exit 1
fi

if [ ! -d "/tmp/${NDK_VERSION}" ] ; then
    export FILENAME=$NDK_VERSION-$HOST_PLATFORM.zip

    (cd '/tmp' \
        && wget http://dl.google.com/android/repository/$FILENAME -O $FILENAME \
        && unzip -q $FILENAME) || exit 1
    unset FILENAME
fi

function _build_arch {
    export ANDROID_NDK_ROOT="/tmp/${NDK_VERSION}"
    export TOOLCHAIN_PATH="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_PLATFORM}/bin"
    export TOOLCHAIN_HOST=$1
    export TOOLCHAIN_COMP=$2
    export TOOLCHAIN_CXXSTL=$3
    export TOOLCHAIN_ARCH=$4
    export TOOLCHAIN_NAME="${TOOLCHAIN_HOST}-${NDK_ABI_VERSION}"

    source ./build.sh
}

# Define the minimum Android API level for the library to run.
# With NDK r20, the minimum SDK version range is [16, 29]
export MIN_SDK_VERSION="21"

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

_build_arch $HOST_ARM $COMP_ARM $CXXSTL_ARM $ARCH_ARM
_build_arch $HOST_X86 $COMP_X86 $CXXSTL_X86 $ARCH_X86

if [[ $MIN_SDK_VERSION -ge 21 ]] ; then
    _build_arch $HOST_ARM64 $COMP_ARM64 $CXXSTL_ARM64 $ARCH_ARM64
    _build_arch $HOST_X86_64 $COMP_X86_64 $CXXSTL_X86_64 $ARCH_X86_64
fi

