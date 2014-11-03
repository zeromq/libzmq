#!/usr/bin/env bash

export ANDROID_NDK_ROOT="/android-ndk"
export TOOLCHAIN_PATH="/android-ndk/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/bin"
export TOOLCHAIN_NAME="arm-linux-androideabi-4.8"
export TOOLCHAIN_HOST="arm-linux-androideabi"
export TOOLCHAIN_ARCH="arm"

source ./build.sh
