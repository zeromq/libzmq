#!/usr/bin/env bash
#
# Copyright (c) 2014, Joe Eli McIlvain
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#
###
#
# https://github.com/jemc/android_build_helper
#   android_build_helper.sh
#
# The following is a helper script for setting up android builds for
# "native" libraries maintained with an autotools build system.
# It merely helps to create the proper cross-compile environment.
# It makes no attempt to wrap the library or make it accessible to Java code;
# the intention is to make the bare library available to other "native" code.
#
# To get the latest version of this script, please download from:
#   https://github.com/jemc/android_build_helper
#
# You are free to modify this script, but if you add improvements,
# please consider submitting a pull request to the aforementioned upstream
# repository for the benefit of other users.
#

# Get directory of current script (if not already set)
# This directory is also the basis for the build directories the get created.
if [ -z "$ANDROID_BUILD_DIR" ]; then
    ANDROID_BUILD_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

# Set up a variable to hold the global failure reasons, separated by newlines
# (Empty string indicates no failure)
ANDROID_BUILD_FAIL=()

function android_build_check_fail {
    if [ ! ${#ANDROID_BUILD_FAIL[@]} -eq 0 ]; then
        echo "Android (${TOOLCHAIN_ARCH}) build failed for the following reasons:"
        for reason in "${ANDROID_BUILD_FAIL[@]}"; do
            local formatted_reason="  ${reason}"
            echo "${formatted_reason}"
        done
        exit 1
    fi
}

function android_build_set_env {
    BUILD_ARCH=$1

    export TOOLCHAIN_PATH="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_PLATFORM}/bin"

    # Set variables for each architecture
    if [ $BUILD_ARCH == "arm" ]; then
        export TOOLCHAIN_HOST="arm-linux-androideabi"
        export TOOLCHAIN_COMP="armv7a-linux-androideabi${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="armeabi-v7a"
        export TOOLCHAIN_ARCH="arm"
    elif [ $BUILD_ARCH == "x86" ]; then
        export TOOLCHAIN_HOST="i686-linux-android"
        export TOOLCHAIN_COMP="i686-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="x86"
        export TOOLCHAIN_ARCH="x86"
    elif [ $BUILD_ARCH == "arm64" ]; then
        export TOOLCHAIN_HOST="aarch64-linux-android"
        export TOOLCHAIN_COMP="aarch64-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="arm64-v8a"
        export TOOLCHAIN_ARCH="arm64"
    elif [ $BUILD_ARCH == "x86_64" ]; then
        export TOOLCHAIN_HOST="x86_64-linux-android"
        export TOOLCHAIN_COMP="x86_64-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="x86_64"
        export TOOLCHAIN_ARCH="x86_64"
    fi

    export ANDROID_BUILD_SYSROOT="${ANDROID_NDK_ROOT}/platforms/android-${MIN_SDK_VERSION}/arch-${TOOLCHAIN_ARCH}"
    export ANDROID_BUILD_PREFIX="${ANDROID_BUILD_DIR}/prefix/${TOOLCHAIN_ARCH}"
}

function android_build_env {
    ##
    # Check that necessary environment variables are set

    if [ -z "$ANDROID_NDK_ROOT" ]; then
        ANDROID_BUILD_FAIL+=("Please set the ANDROID_NDK_ROOT environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r20\")")
    fi

    if [ -z "$TOOLCHAIN_PATH" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_PATH environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r20/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin\")")
    fi

    if [ -z "$TOOLCHAIN_HOST" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_HOST environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"arm-linux-androideabi\")")
    fi

    if [ -z "$TOOLCHAIN_COMP" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_COMP environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"armv7a-linux-androideabi\")")
    fi

    if [ -z "$TOOLCHAIN_ABI" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_ABI environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"armeabi-v7a\")")
    fi

    if [ -z "$TOOLCHAIN_ARCH" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_ARCH environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"arm\")")
    fi

    android_build_check_fail

    ##
    # Check that directories given by environment variables exist

    if [ ! -d "$ANDROID_NDK_ROOT" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_NDK_ROOT directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_NDK_ROOT}")
    fi

    if [ ! -d "$TOOLCHAIN_PATH" ]; then
        ANDROID_BUILD_FAIL+=("The TOOLCHAIN_PATH directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${TOOLCHAIN_PATH}")
    fi

    ##
    # Set up some local variables and check them

    if [ ! -d "$ANDROID_BUILD_SYSROOT" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_BUILD_SYSROOT directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_SYSROOT}")
    fi

    mkdir -p "$ANDROID_BUILD_PREFIX" || {
        ANDROID_BUILD_FAIL+=("Failed to make ANDROID_BUILD_PREFIX directory")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_PREFIX}")
    }

    android_build_check_fail
}

function _android_build_opts_process_binaries {
    local TOOLCHAIN="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${HOST_PLATFORM}"
    local CC="${TOOLCHAIN_PATH}/${TOOLCHAIN_COMP}-clang"
    local CXX="${TOOLCHAIN_PATH}/${TOOLCHAIN_COMP}-clang++"
    local LD="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ld"
    local AS="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-as"
    local AR="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ar"
    local RANLIB="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ranlib"
    local STRIP="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-strip"

    if [ ! -x "${CC}" ]; then
        ANDROID_BUILD_FAIL+=("The CC binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${CC}")
    fi

    if [ ! -x "${CXX}" ]; then
        ANDROID_BUILD_FAIL+=("The CXX binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${CXX}")
    fi

    if [ ! -x "${LD}" ]; then
        ANDROID_BUILD_FAIL+=("The LD binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${LD}")
    fi

    if [ ! -x "${AS}" ]; then
        ANDROID_BUILD_FAIL+=("The AS binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${AS}")
    fi

    if [ ! -x "${AR}" ]; then
        ANDROID_BUILD_FAIL+=("The AR binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${AR}")
    fi

    if [ ! -x "${RANLIB}" ]; then
        ANDROID_BUILD_FAIL+=("The RANLIB binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${RANLIB}")
    fi

    if [ ! -x "${STRIP}" ]; then
        ANDROID_BUILD_FAIL+=("The STRIP binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${STRIP}")
    fi

    ANDROID_BUILD_OPTS+=("TOOLCHAIN=${TOOLCHAIN}")
    ANDROID_BUILD_OPTS+=("CC=${CC}")
    ANDROID_BUILD_OPTS+=("CXX=${CXX}")
    ANDROID_BUILD_OPTS+=("LD=${LD}")
    ANDROID_BUILD_OPTS+=("AS=${AS}")
    ANDROID_BUILD_OPTS+=("AR=${AR}")
    ANDROID_BUILD_OPTS+=("RANLIB=${RANLIB}")
    ANDROID_BUILD_OPTS+=("STRIP=${STRIP}")

    android_build_check_fail
}

# Set the ANDROID_BUILD_OPTS variable to a bash array of configure options
function android_build_opts {
    ANDROID_BUILD_OPTS=()

    _android_build_opts_process_binaries

    local LIBS="-lc -lgcc -ldl -lm -llog -lc++_shared"
    local LDFLAGS="-L${ANDROID_BUILD_PREFIX}/lib"
    LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/llvm-libc++/libs/${TOOLCHAIN_ABI}"
    CFLAGS+=" -D_GNU_SOURCE -D_REENTRANT -D_THREAD_SAFE"
    CPPFLAGS+=" -I${ANDROID_BUILD_PREFIX}/include"

    ANDROID_BUILD_OPTS+=("CFLAGS=${CFLAGS} ${ANDROID_BUILD_EXTRA_CFLAGS}")
    ANDROID_BUILD_OPTS+=("CPPFLAGS=${CPPFLAGS} ${ANDROID_BUILD_EXTRA_CPPFLAGS}")
    ANDROID_BUILD_OPTS+=("CXXFLAGS=${CXXFLAGS} ${ANDROID_BUILD_EXTRA_CXXFLAGS}")
    ANDROID_BUILD_OPTS+=("LDFLAGS=${LDFLAGS} ${ANDROID_BUILD_EXTRA_LDFLAGS}")
    ANDROID_BUILD_OPTS+=("LIBS=${LIBS} ${ANDROID_BUILD_EXTRA_LIBS}")

    ANDROID_BUILD_OPTS+=("PKG_CONFIG_LIBDIR=${ANDROID_NDK_ROOT}/prebuilt/${HOST_PLATFORM}/lib/pkgconfig")
    ANDROID_BUILD_OPTS+=("PKG_CONFIG_PATH=${ANDROID_BUILD_PREFIX}/lib/pkgconfig")
    ANDROID_BUILD_OPTS+=("PKG_CONFIG_SYSROOT_DIR=${ANDROID_BUILD_SYSROOT}")
    ANDROID_BUILD_OPTS+=("PKG_CONFIG_DIR=")
    ANDROID_BUILD_OPTS+=("--with-sysroot=${ANDROID_BUILD_SYSROOT}")
    ANDROID_BUILD_OPTS+=("--host=${TOOLCHAIN_HOST}")
    ANDROID_BUILD_OPTS+=("--prefix=${ANDROID_BUILD_PREFIX}")

    android_build_check_fail
}

# Parse readelf output to verify the correct linking of libraries.
#   The first argument should be the soname of the newly built library.
#   The rest of the arguments should be the sonames of dependencies.
#   All sonames should be unversioned for android (no trailing numbers).
function android_build_verify_so {
    local soname="$1"
    shift # Get rid of first argument - the rest represent dependencies

    local sofile="${ANDROID_BUILD_PREFIX}/lib/${soname}"
    if [ ! -f "${sofile}" ]; then
        ANDROID_BUILD_FAIL+=("Found no library named ${soname}")
        ANDROID_BUILD_FAIL+=("  ${sofile}")
    fi
    android_build_check_fail

    local READELF="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-readelf"
    if command -v ${READELF} >/dev/null 2>&1 ; then
        local readelf_bin="${READELF}"
    elif command -v readelf >/dev/null 2>&1 ; then
        local readelf_bin="readelf"
    elif command -v greadelf >/dev/null 2>&1 ; then
        local readelf_bin="greadelf"
    else
        ANDROID_BUILD_FAIL+=("Could not find any of readelf, greadelf, or ${READELF}")
    fi
    android_build_check_fail

    local elfoutput=$(LC_ALL=C $readelf_bin -d ${sofile})

    local soname_regexp='soname: \[([[:alnum:]\.]+)\]'
    if [[ $elfoutput =~ $soname_regexp ]]; then
        local parsed_soname="${BASH_REMATCH[1]}"
        if [ "${parsed_soname}" != "${soname}" ]; then
            ANDROID_BUILD_FAIL+=("Actual soname of library ${soname} is incorrect (or versioned):")
            ANDROID_BUILD_FAIL+=("  ${parsed_soname}")
        fi
    else
        ANDROID_BUILD_FAIL+=("Failed to meaningfully parse readelf output for library ${soname}:")
        ANDROID_BUILD_FAIL+=("  ${elfoutput}")
    fi

    for dep_soname do
        if [[ $elfoutput != *"library: [${dep_soname}]"* ]]; then
            ANDROID_BUILD_FAIL+=("Library ${soname} was expected to be linked to library with soname:")
            ANDROID_BUILD_FAIL+=("  ${dep_soname}")
        fi
    done

    android_build_check_fail
}
