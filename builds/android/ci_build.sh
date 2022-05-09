#!/usr/bin/env bash

export NDK_VERSION=android-ndk-r24
export ANDROID_NDK_ROOT="/tmp/${NDK_VERSION}"

case $(uname | tr '[:upper:]' '[:lower:]') in
  linux*)
    HOST_PLATFORM=linux
    ;;
  darwin*)
    HOST_PLATFORM=darwin
    ;;
  *)
    echo "Unsupported platform"
    exit 1
    ;;
esac

if [ ! -d "${ANDROID_NDK_ROOT}" ]; then
    export FILENAME=$NDK_VERSION-$HOST_PLATFORM.zip

    (cd '/tmp' \
        && wget http://dl.google.com/android/repository/$FILENAME -O $FILENAME &> /dev/null \
        && unzip -q $FILENAME) || exit 1
    unset FILENAME
fi

./build.sh "arm"
./build.sh "arm64"
./build.sh "x86"
./build.sh "x86_64"
