#!/usr/bin/env bash

export ANDROID_NDK_ROOT="/home/jemc/android/android-ndk-r9d"
export TOOLCHAIN_PATH="/home/jemc/android/android-ndk-r9d/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/bin"
export TOOLCHAIN_NAME="arm-linux-androideabi-4.8"
export TOOLCHAIN_HOST="arm-linux-androideabi"
export TOOLCHAIN_ARCH="arm"

./build.sh
