# Android Build

## Prerequisites

The last known NDK is automatically downloaded, if not specified otherwise.

## Configuration

This project is tested against Android NDK version r25, but should
support older ones too.

This project uses NDK `android-ndk-r25`, by default, but you can specify
a different one:

    export NDK_VERSION=android-ndk-r23c

If you already have installed your favorite NDK somewhere, all you have to
do is to export and set NDK_VERSION and ANDROID_NDK_ROOT environment
variables, e.g:

    export NDK_VERSION=android-ndk-r23b
    export ANDROID_NDK_ROOT=$HOME/${NDK_VERSION}

**Important:** ANDROID_NDK_ROOT must be an absolute path !

If you specify only NDK_VERSION, ANDROID_NDK_ROOT will be automatically set 
to its default:

    export ANDROID_NDK_ROOT=/tmp/${NDK_VERSION}

To specify the minimum SDK version set the environment variable below:

    export MIN_SDK_VERSION=21   # Default value if unset

To specify the build directory set the environment variable below:

    export ANDROID_BUILD_DIR=${HOME}/android_build

**Important:** ANDROID_BUILD_ROOT must be an absolute path !

All libraries will be generated under:

    ${ANDROID_BUILD_DIR}/prefix/<arch>/lib

where <_arch_> is one of `arm`, `arm64`, `x86` or `x86_64`.

You can also check configuration variables in `build.sh` itself, in its
"Configuration & tuning options" comment block.

The variable CURVE accepts 3 different values: 

    ""          : LIBZMQ is built without any encryption support.
    "libsodium" : LIBZMQ is built with LIBSODIUM encryption support (see below).
    "tweetnacl" : LIBZMQ is build with embedded encryption support.

## LIBSODIUM

LIBSODIUM is built along with LIBZMQ, when CURVE="libsodium".

- If you have your own clone of LIBSODIUM, set LIBSODIUM_ROOT to point to
its folder.
- If the variable LIBSODIUM_ROOT is not set, LIBZMQ will look for a folder
'libsodium' close to his own one.
- If no folder 'libsodium' exists, then LIBZMQ will clone LIBSODIUM from its
official STABLE branch.

## Build

See chapter [Configuration](#configuration) for configuration options and
other details.

Select your prefered parameters:

    export XXX=xxx
    export YYY=yyy
    ...

And, in the android directory, run:

    ./build.sh [ arm | arm64 | x86 | x86_64 ]

Parameter selection and the calls to build.sh can be located in a
SHELL script, like in ci_build.sh.

## Dockerfile

An example of Docker file is provided, for Ubuntu 22.04

Minimal changes are required to support Debian 9 to 11.

Minimal changes are required to support CentOS (7 only), Rocky Linux (8 & 9),
and many Fedora (22 to 37).

