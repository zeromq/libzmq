#!/usr/bin/env bash

NDK_VER=android-ndk-r11c
NDK_ABI_VER=4.9

if [ $TRAVIS_OS_NAME == "linux" ]
then
    NDK_PLATFORM=linux-x86_64
elif [ $TRAVIS_OS_NAME == "osx" ]
then
    NDK_PLATFORM=darwin-x86_64
else
    echo "Unsupported platform $TRAVIS_OS_NAME"
    exit 1
fi

export FILENAME=$NDK_VER-$NDK_PLATFORM.zip

(cd '/tmp' \
    && wget http://dl.google.com/android/repository/$FILENAME \
    && unzip $FILENAME &> /dev/null ) || exit 1
unset FILENAME

export ANDROID_NDK_ROOT="/tmp/$NDK_VER"
export TOOLCHAIN_PATH="$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-$NDK_ABI_VER/prebuilt/$NDK_PLATFORM/bin"
export TOOLCHAIN_NAME="arm-linux-androideabi-$NDK_ABI_VER"
export TOOLCHAIN_HOST="arm-linux-androideabi"
export TOOLCHAIN_ARCH="arm"

source ./build.sh
