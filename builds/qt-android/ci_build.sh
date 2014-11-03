#!/usr/bin/env bash

ANDROID_NDK_ROOT="/android-ndk"
TOOLCHAIN_PATH="/android-ndk/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/bin"
TOOLCHAIN_NAME="arm-linux-androideabi-4.8"
TOOLCHAIN_HOST="arm-linux-androideabi"
TOOLCHAIN_ARCH="arm"

export ANDROID_NDK_ROOT
export TOOLCHAIN_PATH
export TOOLCHAIN_NAME
export TOOLCHAIN_HOST
export TOOLCHAIN_ARCH

./build.sh
