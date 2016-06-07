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
        echo "Android build failed for the following reasons:"
        for reason in "${ANDROID_BUILD_FAIL[@]}"; do
            local formatted_reason="  ${reason}"
            echo "${formatted_reason}"
        done
        exit 1
    fi
}

function android_build_env {
    ##
    # Check that necessary environment variables are set
    
    if [ -z "$ANDROID_NDK_ROOT" ]; then
        ANDROID_BUILD_FAIL+=("Please set the ANDROID_NDK_ROOT environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r11c\")")
    fi
    
    if [ -z "$TOOLCHAIN_PATH" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_PATH environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r11c/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin\")")
    fi
    
    if [ -z "$TOOLCHAIN_NAME" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_NAME environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"arm-linux-androideabi-4.9\")")
    fi
    
    if [ -z "$TOOLCHAIN_HOST" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_HOST environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"arm-linux-androideabi\")")
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
    
    ANDROID_BUILD_SYSROOT="${ANDROID_NDK_ROOT}/platforms/android-9/arch-${TOOLCHAIN_ARCH}"
    
    if [ ! -d "$ANDROID_BUILD_SYSROOT" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_BUILD_SYSROOT directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_SYSROOT}")
    fi
    
    ANDROID_BUILD_PREFIX="${ANDROID_BUILD_DIR}/prefix/${TOOLCHAIN_NAME}"
    
    mkdir -p "$ANDROID_BUILD_PREFIX" || {
        ANDROID_BUILD_FAIL+=("Failed to make ANDROID_BUILD_PREFIX directory")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_PREFIX}")
    }
    
    android_build_check_fail
}

function _android_build_opts_process_binaries {
    local CPP="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-cpp"
    local CC="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-gcc"
    local CXX="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-g++"
    local LD="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ld"
    local AS="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-as"
    local AR="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ar"
    local RANLIB="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ranlib"
    
    if [ ! -x "${CPP}" ]; then
        ANDROID_BUILD_FAIL+=("The CPP binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${CPP}")
    fi
    
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
    
    ANDROID_BUILD_OPTS+=("CPP=${CPP}")
    ANDROID_BUILD_OPTS+=("CC=${CC}")
    ANDROID_BUILD_OPTS+=("CXX=${CXX}")
    ANDROID_BUILD_OPTS+=("LD=${LD}")
    ANDROID_BUILD_OPTS+=("AS=${AS}")
    ANDROID_BUILD_OPTS+=("AR=${AR}")
    ANDROID_BUILD_OPTS+=("RANLIB=${RANLIB}")
    
    android_build_check_fail
}

function _android_build_opts_process_cxx_stl {
    case "${ANDROID_BUILD_CXXSTL}" in
    stlport_static)
        LIBS+=" -lstlport_static"
        CPPFLAGS+=" -I${ANDROID_NDK_ROOT}/sources/cxx-stl/stlport/stlport"
        case "${TOOLCHAIN_ARCH}" in
        arm)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/stlport/libs/armeabi"
        ;;
        x86)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/stlport/libs/x86"
        ;;
        mips)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/stlport/libs/mips"
        ;;
        *)
            ANDROID_BUILD_FAIL+=("Unknown combination for ANDROID_BUILD_CXXSTL and TOOLCHAIN_ARCH")
            ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_CXXSTL}")
            ANDROID_BUILD_FAIL+=("  ${TOOLCHAIN_ARCH}")
        ;;
        esac
    ;;
    gnustl_shared_49)
        LIBS+=" -lgnustl_shared"
        CPPFLAGS+=" -I${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/include"
        case "${TOOLCHAIN_ARCH}" in
        arm)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/armeabi"
            CPPFLAGS+=" -I${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/armeabi/include"
        ;;
        x86)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/x86"
            CPPFLAGS+=" -I${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/x86/include"
        ;;
        mips)
            LDFLAGS+=" -L${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/mips"
            CPPFLAGS+=" -I${ANDROID_NDK_ROOT}/sources/cxx-stl/gnu-libstdc++/4.9/libs/mips/include"
        ;;
        *)
            ANDROID_BUILD_FAIL+=("Unknown combination for ANDROID_BUILD_CXXSTL and TOOLCHAIN_ARCH")
            ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_CXXSTL}")
            ANDROID_BUILD_FAIL+=("  ${TOOLCHAIN_ARCH}")
        ;;
        esac
    ;;
    '');;
    *)
        ANDROID_BUILD_FAIL+=("Unknown value for ANDROID_BUILD_CXXSTL")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_CXXSTL}")
    ;;
    esac
}

# Set the ANDROID_BUILD_OPTS variable to a bash array of configure options
function android_build_opts {
    ANDROID_BUILD_OPTS=()
    
    local CFLAGS="--sysroot=${ANDROID_BUILD_SYSROOT} -I${ANDROID_BUILD_PREFIX}/include"
    local CPPFLAGS="--sysroot=${ANDROID_BUILD_SYSROOT} -I${ANDROID_BUILD_PREFIX}/include"
    local CXXFLAGS="--sysroot=${ANDROID_BUILD_SYSROOT} -I${ANDROID_BUILD_PREFIX}/include"
    local LDFLAGS="-L${ANDROID_BUILD_PREFIX}/lib"
    local LIBS="-lc -lgcc -ldl"
    
    _android_build_opts_process_binaries
    _android_build_opts_process_cxx_stl
    
    ANDROID_BUILD_OPTS+=("CFLAGS=${CFLAGS} ${ANDROID_BUILD_EXTRA_CFLAGS}")
    ANDROID_BUILD_OPTS+=("CPPFLAGS=${CPPFLAGS} ${ANDROID_BUILD_EXTRA_CPPFLAGS}")
    ANDROID_BUILD_OPTS+=("CXXFLAGS=${CXXFLAGS} ${ANDROID_BUILD_EXTRA_CXXFLAGS}")
    ANDROID_BUILD_OPTS+=("LDFLAGS=${LDFLAGS} ${ANDROID_BUILD_EXTRA_LDFLAGS}")
    ANDROID_BUILD_OPTS+=("LIBS=${LIBS} ${ANDROID_BUILD_EXTRA_LIBS}")
    
    ANDROID_BUILD_OPTS+=("PKG_CONFIG_PATH=${ANDROID_BUILD_PREFIX}/lib/pkgconfig")
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
    
    if command -v readelf >/dev/null 2>&1 ; then
        local readelf_bin="readelf"
    elif command -v greadelf >/dev/null 2>&1 ; then
        local readelf_bin="greadelf"
    else
        ANDROID_BUILD_FAIL+=("Could not find [g]readelf")
    fi
    android_build_check_fail

    local elfoutput=$($readelf_bin -d ${sofile})
    
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
