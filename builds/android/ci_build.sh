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
export ANDROID_BUILD_DIR="${ANDROID_BUILD_DIR:-${PWD}}"

# Cleanup.
rm -rf /tmp/android_build/
rm -rf "${PWD}/prefix"
rm -rf /tmp/tmp-deps
mkdir -p /tmp/tmp-deps

./build.sh "arm"
./build.sh "arm64"
./build.sh "x86"
./build.sh "x86_64"
