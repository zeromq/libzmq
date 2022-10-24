#!/usr/bin/env bash

set -e

# Use directory of current script as the working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
LIBZMQ_ROOT="$(cd ../.. && pwd)"

########################################################################
# Configuration & tuning options.
########################################################################
# Set default values used in ci builds
export NDK_VERSION="${NDK_VERSION:-android-ndk-r25}"

# Set default path to find Android NDK.
# Must be of the form <path>/${NDK_VERSION} !!
export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-/tmp/${NDK_VERSION}}"

# With NDK r22b, the minimum SDK version range is [16, 31].
# Since NDK r24, the minimum SDK version range is [19, 31].
# SDK version 21 is the minimum version for 64-bit builds.
export MIN_SDK_VERSION=${MIN_SDK_VERSION:-21}

# Use directory of current script as the build directory
# ${ANDROID_BUILD_DIR}/prefix/<build_arch>/lib will contain produced libraries
export ANDROID_BUILD_DIR="${ANDROID_BUILD_DIR:-${PWD}}"

# Clean before processing
export ANDROID_BUILD_CLEAN="${ANDROID_BUILD_CLEAN:-}"

# Select CURVE implementation:
# - ""               # Do not use any CURVE implementation.
# - "libsodium"      # Use LIBSODIUM implementation.
# - "tweetnacl"      # Use internal TWEETNACL implementation.
export CURVE="${CURVE:-}"

########################################################################
# Utilities
########################################################################
function usage {
    echo "LIBZMQ - Usage:"
    echo "  export XXX=yyy"
    echo "  ./build.sh [ arm | arm64 | x86 | x86_64 ]"
    echo ""
    echo "See this file (configuration & tuning options) for details"
    echo "on variables XXX and their values xxx"
    exit 1
}

# Initialize env variable XXX_ROOT, given dependency name "xxx".
# If XXX_ROOT is not set:
#    If a folder xxx exists close to current clone, set XXX_ROOT with it.
#    Else, set XXX_ROOT with /tmp/tmp-deps/xxx.
# Else
#    Verify that folder XXX_ROOT exists.
function init_dependency_root {
    local lib_name
    lib_name="$1"
    local variable_name
    variable_name="$(echo "${lib_name}" | tr '[:lower:]' '[:upper:]')_ROOT"
    local variable_value
    variable_value="$(eval echo "\${${variable_name}}")"

    if [ -z "${variable_value}" ] ; then
        if [ -d "${LIBZMQ_ROOT}/../${lib_name}" ] ; then
            eval "export ${variable_name}=\"$(cd "${LIBZMQ_ROOT}/../${lib_name}" && pwd)\""
        else
            eval "export ${variable_name}=\"/tmp/tmp-deps/${lib_name}\""
        fi
        variable_value="$(eval echo "\${${variable_name}}")"
    elif [ ! -d "${variable_value}" ] ; then
        echo "LIBZMQ - Error: Folder '${variable_value}' does not exist."
        exit 1
    fi

    echo "LIBZMQ - ${variable_name}=${variable_value}"
}

########################################################################
# Sanity checks
########################################################################
BUILD_ARCH="$1"
[ -z "${BUILD_ARCH}" ] && usage

# Set ROOT path for LIBSODIUM source tree, if CURVE is "libsodium"
if [ "${CURVE}x" = "libsodiumx" ] ; then
    init_dependency_root "libsodium"
fi

########################################################################
# Compilation
########################################################################
# Choose a C++ standard library implementation from the ndk
export ANDROID_BUILD_CXXSTL="gnustl_shared_49"

# Additional flags for LIBTOOL, for LIBZMQ and other dependencies.
export LIBTOOL_EXTRA_LDFLAGS='-avoid-version'

# Get access to android_build functions and variables
# Perform some sanity checks and calculate some variables.
source ./android_build_helper.sh

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_set_env "${BUILD_ARCH}"
android_download_ndk
android_build_env
android_build_opts

# Check for environment variable to clear the prefix and do a clean build
if [[ $ANDROID_BUILD_CLEAN ]]; then
    android_build_trace "Doing a clean build (removing previous build and dependencies)..."
    rm -rf "${ANDROID_BUILD_PREFIX:-android-build-prefix-not-set}"/*

    # Called shells MUST not clean after ourselves !
    export ANDROID_BUILD_CLEAN=""
fi

VERIFY=("libzmq.so")
if [ -z "${CURVE}" ]; then
    CURVE="--disable-curve"
elif [ "${CURVE}" == "libsodium" ]; then
    CURVE="--with-libsodium=yes"
    VERIFY+=("libsodium.so")
    ##
    # Build LIBSODIUM from latest STABLE branch

    (android_build_verify_so "libsodium.so" &> /dev/null) || {
        if [ ! -d "${LIBSODIUM_ROOT}" ] ; then
            android_clone_library "LIBSODIUM" "${LIBSODIUM_ROOT}" "https://github.com/jedisct1/libsodium.git" "stable"
        fi

        (
            CONFIG_OPTS=()
            CONFIG_OPTS+=("--quiet")
            CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
            CONFIG_OPTS+=("--disable-soname-versions")

            android_build_library "LIBSODIUM" "${LIBSODIUM_ROOT}"
        ) || exit 1
    }
elif [ $CURVE == "tweetnacl" ]; then
    # Default
    CURVE=""
fi

##
# Build libzmq from local source

(android_build_verify_so "${VERIFY[@]}" &> /dev/null) || {
    (cd "${LIBZMQ_ROOT}" && ( make clean || : ) && rm -f ./config.status ) || exit 1

    (
        CONFIG_OPTS=()
        CONFIG_OPTS+=("--quiet")
        CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
        CONFIG_OPTS+=("${CURVE}")
        CONFIG_OPTS+=("--without-docs")

        android_build_library "LIBZMQ" "${LIBZMQ_ROOT}"
    ) || exit 1
}

##
# Fetch the STL as well.

cp "${ANDROID_STL_ROOT}/${ANDROID_STL}" "${ANDROID_BUILD_PREFIX}/lib/."

##
# Verify shared libraries in prefix

android_build_verify_so "${VERIFY[@]}" "${ANDROID_STL}"
android_build_trace "Android build successful"
