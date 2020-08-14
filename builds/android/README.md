# Android Build

## Prerequisites

You need the Android Native Development Kit (NDK) installed. See
[here](https://developer.android.com/ndk) to download it.

This project is tested against Android NDK version r21d.

If you installed version r21d all you have to do is to expose the NDK root
directory as environment variable, e.g:

    export ANDROID_NDK_ROOT=$HOME/android-ndk-r21d

If you installed another version you have to expose the NDK root directory as
well as the NDK version, e.g:

    export ANDROID_NDK_ROOT=$HOME/android-ndk-r17c
    export NDK_VERSION=android-ndk-r17c

To specify the minimum sdk version set the environment variable below:

    export MIN_SDK_VERSION=21   # Default value if unset

To specify the prefix directory set the environment variable below:

    export ANDROID_BUILD_DIR=./builds/android/prefix/<android_arch> # Default value if unset

## Build

In the android directory, run:

    ./build.sh [ arm | arm64 | x86 | x86_64 ]
