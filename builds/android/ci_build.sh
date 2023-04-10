#!/usr/bin/env bash
#
#   Exit if any step fails
set -e

# Use directory of current script as the working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"

# Configuration
export NDK_VERSION="${NDK_VERSION:-android-ndk-r25}"
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-/tmp/${NDK_VERSION}}"
export MIN_SDK_VERSION=${MIN_SDK_VERSION:-21}
export ANDROID_BUILD_DIR="${ANDROID_BUILD_DIR:-${PWD}/.build}"
export ANDROID_BUILD_CLEAN="${ANDROID_BUILD_CLEAN:-yes}"
export ANDROID_DEPENDENCIES_DIR="${ANDROID_DEPENDENCIES_DIR:-${PWD}/.deps}"

# Cleanup.
if [ "${ANDROID_BUILD_CLEAN}" = "yes" ] ; then
    rm -rf   "${ANDROID_BUILD_DIR}/prefix"
    mkdir -p "${ANDROID_BUILD_DIR}/prefix"
    rm -rf   "${ANDROID_DEPENDENCIES_DIR}"
    mkdir -p "${ANDROID_DEPENDENCIES_DIR}"

    # Called shells MUST not clean after ourselves !
    export ANDROID_BUILD_CLEAN="no"
fi

./build.sh "arm"
./build.sh "arm64"
./build.sh "x86"
./build.sh "x86_64"
