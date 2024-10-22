#!/usr/bin/env bash
#
#   Exit if any step fails
set -e

# Use directory of current script as the working directory
cd "$( dirname "${BASH_SOURCE[0]}" )"
PROJECT_ROOT="$(cd ../.. && pwd)"

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

# Where to download our dependencies: default to /tmp/tmp-deps
export ANDROID_DEPENDENCIES_DIR="${ANDROID_DEPENDENCIES_DIR:-/tmp/tmp-deps}"

# Clean before processing
export ANDROID_BUILD_CLEAN="${ANDROID_BUILD_CLEAN:-no}"

# Set this to 'no', to enable verbose ./configure
export CI_CONFIG_QUIET="${CI_CONFIG_QUIET:-no}"

# Select CURVE implementation:
# - ""               # Do not use any CURVE implementation.
# - "libsodium"      # Use LIBSODIUM implementation.
export CURVE="${CURVE:-}"

# By default, dependencies will be cloned to /tmp/tmp-deps.
# If you have your own source tree for LIBSODIUM, uncomment
# the line below, and provide its absolute path:
#    export LIBSODIUM_ROOT="<absolute_path_to_LIBSODIUM_source_tree>"

########################################################################
# Utilities
########################################################################
# Get access to android_build functions and variables
# Perform some sanity checks and calculate some variables.
source "${PROJECT_ROOT}/builds/android/android_build_helper.sh"

function usage {
    echo "LIBZMQ - Usage:"
    echo "  export XXX=xxx"
    echo "  ./build.sh [ arm | arm64 | x86 | x86_64 ]"
    echo ""
    echo "See this file (configuration & tuning options) for details"
    echo "on variables XXX and their values xxx"
    exit 1
}

########################################################################
# Sanity checks
########################################################################
BUILD_ARCH="$1"
[ -z "${BUILD_ARCH}" ] && usage

# Set ROOT path for LIBSODIUM source tree, if CURVE is "libsodium"
if [ "${CURVE}x" = "libsodiumx" ] ; then
    # Check or initialize LIBSODIUM_ROOT
    android_init_dependency_root "libsodium"
fi

########################################################################
# Compilation
########################################################################
# Choose a C++ standard library implementation from the ndk
export ANDROID_BUILD_CXXSTL="gnustl_shared_49"

# Additional flags for LIBTOOL, for LIBZMQ and other dependencies.
export LIBTOOL_EXTRA_LDFLAGS='-avoid-version'

# Set up android build environment and set ANDROID_BUILD_OPTS array
android_build_set_env "${BUILD_ARCH}"
android_download_ndk
android_build_env
android_build_opts

# Check for environment variable to clear the prefix and do a clean build
if [ "${ANDROID_BUILD_CLEAN}" = "yes" ]; then
    android_build_trace "Doing a clean build (removing previous build and dependencies)..."
    rm -rf "${ANDROID_BUILD_PREFIX:?}"/*

    # Called shells MUST not clean after ourselves !
    export ANDROID_BUILD_CLEAN="no"
fi

DEPENDENCIES=()
if [ -z "${CURVE}" ]; then
    CURVE="--disable-curve"
elif [ "${CURVE}" == "libsodium" ]; then
    CURVE="--with-libsodium=yes"
    DEPENDENCIES+=("libsodium.so")
    ##
    # Build LIBSODIUM from latest STABLE branch

    (android_build_verify_so "libsodium.so" &> /dev/null) || {
        if [ ! -d "${LIBSODIUM_ROOT}" ] ; then
            android_clone_library "LIBSODIUM" "${LIBSODIUM_ROOT}" "https://github.com/jedisct1/libsodium.git" "stable"
        fi

        (
            CONFIG_OPTS=()
            [ "${CI_CONFIG_QUIET}" = "yes" ] && CONFIG_OPTS+=("--quiet")
            CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
            CONFIG_OPTS+=("--without-docs")
            CONFIG_OPTS+=("--disable-soname-versions")

            android_build_library "LIBSODIUM" "${LIBSODIUM_ROOT}"
        ) || exit 1
    }
fi

##
# Build libzmq from local source

(android_build_verify_so "libzmq.so" "${DEPENDENCIES[@]}" &> /dev/null) || {
    (
        CONFIG_OPTS=()
        [ "${CI_CONFIG_QUIET}" = "yes" ] && CONFIG_OPTS+=("--quiet")
        CONFIG_OPTS+=("${ANDROID_BUILD_OPTS[@]}")
        CONFIG_OPTS+=("${CURVE}")
        CONFIG_OPTS+=("--without-docs")

        android_build_library "LIBZMQ" "${PROJECT_ROOT}"
    ) || exit 1
}

##
# Fetch the STL as well.

cp "${ANDROID_STL_ROOT}/${ANDROID_STL}" "${ANDROID_BUILD_PREFIX}/lib/."

##
# Verify shared libraries in prefix
for library in "libzmq.so" "${DEPENDENCIES[@]}" ; do
    android_build_verify_so "${library}"
done

android_build_verify_so "libzmq.so" "${DEPENDENCIES[@]}" "${ANDROID_STL}"
android_build_trace "Android build successful"
