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
# Courtesy of Joe Eli McIlvain; original code at:
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
# You are free to modify and redistribute this script, but if you add
# improvements, please consider submitting a pull request or patch to the
# aforementioned upstream repository for the benefit of other users.
#
# This script is provided with no express or implied warranties.
#

########################################################################
# Utilities & helper functions
########################################################################
function android_build_trace {
    if [ -n "${BUILD_ARCH}" ] ; then
        echo "LIBZMQ (${BUILD_ARCH}) - $*"
    else
        echo "LIBZMQ - $*"
    fi
}

function android_build_check_fail {
    if [ ! ${#ANDROID_BUILD_FAIL[@]} -eq 0 ]; then
        android_build_trace "Android build failed for the following reasons:"
        for reason in "${ANDROID_BUILD_FAIL[@]}"; do
            local formatted_reason="  ${reason}"
            echo "${formatted_reason}"
        done
        exit 1
    fi
}

function android_download_ndk {
    if [ -d "${ANDROID_NDK_ROOT}" ] ; then
        # NDK folder detected, let's assume it's valid ...
        android_build_trace "Using existing NDK folder '${ANDROID_NDK_ROOT}'."
        return
    fi
    if [ ! -d  "$(dirname "${ANDROID_NDK_ROOT}")" ] ; then
        ANDROID_BUILD_FAIL+=("Cannot download NDK in a non existing folder")
        ANDROID_BUILD_FAIL+=("  $(dirname "${ANDROID_NDK_ROOT}/")")
    fi

    android_build_check_fail

    local filename
    local platform="$(uname | tr '[:upper:]' '[:lower:]')"
    case "${platform}" in
        linux*)
            if [ "${NDK_NUMBER}" -ge 2300 ] ; then
                # Since NDK 23, NDK archives are renamed.
                filename=${NDK_VERSION}-linux.zip
            else
                filename=${NDK_VERSION}-linux-x86_64.zip
            fi
            ;;
        darwin*)
            if [ "${NDK_NUMBER}" -ge 2300 ] ; then
                # Since NDK 23, NDK archives are renamed.
                filename=${NDK_VERSION}-darwin.zip
            else
                filename=${NDK_VERSION}-darwin-x86_64.zip
            fi
            ;;
        *)    android_build_trace "Unsupported platform ('${platform}')" ; exit 1 ;;
    esac

    if [ -z "${filename}" ] ; then
        ANDROID_BUILD_FAIL+=("Unable to detect NDK filename.")
    fi

    android_build_check_fail

    android_build_trace "Downloading NDK '${NDK_VERSION}'..."
    (
        cd "$(dirname "${ANDROID_NDK_ROOT}")" \
        && rm -f "${filename}" \
        && wget -q "http://dl.google.com/android/repository/${filename}" -O "${filename}" \
        && android_build_trace "Extracting NDK '${filename}'..." \
        && unzip -q "${filename}" \
        && android_build_trace "NDK extracted under '${ANDROID_NDK_ROOT}'."
    ) || {
        ANDROID_BUILD_FAIL+=("Failed to install NDK ('${NDK_VERSION}')")
        ANDROID_BUILD_FAIL+=("  ${filename}")
    }

    android_build_check_fail
}

function android_build_set_env {
    BUILD_ARCH=$1

    local platform="$(uname | tr '[:upper:]' '[:lower:]')"
    case "${platform}" in
        linux*)
            export ANDROID_BUILD_PLATFORM=linux-x86_64
            ;;
        darwin*)
            export ANDROID_BUILD_PLATFORM=darwin-x86_64
            ;;
        *)    android_build_trace "Unsupported platform ('${platform}')" ; exit 1 ;;
    esac

    export ANDROID_BUILD_TOOLCHAIN="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/${ANDROID_BUILD_PLATFORM}"
    export TOOLCHAIN_PATH="${ANDROID_BUILD_TOOLCHAIN}/bin"

    # Set variables for each architecture
    if [ "${BUILD_ARCH}" == "arm" ]; then
        export TOOLCHAIN_HOST="arm-linux-androideabi"
        export TOOLCHAIN_COMP="armv7a-linux-androideabi${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="armeabi-v7a"
        export TOOLCHAIN_ARCH="arm"
    elif [ "${BUILD_ARCH}" == "x86" ]; then
        export TOOLCHAIN_HOST="i686-linux-android"
        export TOOLCHAIN_COMP="i686-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="x86"
        export TOOLCHAIN_ARCH="x86"
    elif [ "${BUILD_ARCH}" == "arm64" ]; then
        export TOOLCHAIN_HOST="aarch64-linux-android"
        export TOOLCHAIN_COMP="aarch64-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="arm64-v8a"
        export TOOLCHAIN_ARCH="arm64"
    elif [ "${BUILD_ARCH}" == "x86_64" ]; then
        export TOOLCHAIN_HOST="x86_64-linux-android"
        export TOOLCHAIN_COMP="x86_64-linux-android${MIN_SDK_VERSION}"
        export TOOLCHAIN_ABI="x86_64"
        export TOOLCHAIN_ARCH="x86_64"
    fi

    # Since NDK r22 the "platforms" dir got removed
    if [ -d "${ANDROID_NDK_ROOT}/platforms" ]; then
        export ANDROID_BUILD_SYSROOT="${ANDROID_NDK_ROOT}/platforms/android-${MIN_SDK_VERSION}/arch-${TOOLCHAIN_ARCH}"
    else
        export ANDROID_BUILD_SYSROOT="${ANDROID_BUILD_TOOLCHAIN}/sysroot"
    fi
    export ANDROID_BUILD_PREFIX="${ANDROID_BUILD_DIR}/prefix/${TOOLCHAIN_ARCH}"

    # Since NDK r25, libc++_shared.so is no more in 'sources/cxx-stl/...'
    export ANDROID_STL="libc++_shared.so"
    if [ -x "${ANDROID_NDK_ROOT}/sources/cxx-stl/llvm-libc++/libs/${TOOLCHAIN_ABI}/${ANDROID_STL}" ] ; then
        export ANDROID_STL_ROOT="${ANDROID_NDK_ROOT}/sources/cxx-stl/llvm-libc++/libs/${TOOLCHAIN_ABI}"
    else
        export ANDROID_STL_ROOT="${ANDROID_BUILD_SYSROOT}/usr/lib/${TOOLCHAIN_HOST}"

        # NDK 25 requires -L<path-to-libc.so> ...
        # I don't understand why, but without it, ./configure fails to build a valid 'conftest'.
        export ANDROID_LIBC_ROOT="${ANDROID_BUILD_SYSROOT}/usr/lib/${TOOLCHAIN_HOST}/${MIN_SDK_VERSION}"
    fi
}

function android_build_env {
    ##
    # Check that necessary environment variables are set

    if [ -z "$ANDROID_NDK_ROOT" ]; then
        ANDROID_BUILD_FAIL+=("Please set the ANDROID_NDK_ROOT environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r25\")")
    fi

    if [ -z "$ANDROID_BUILD_TOOLCHAIN" ]; then
        ANDROID_BUILD_FAIL+=("Please set the ANDROID_BUILD_TOOLCHAIN environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r25/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64\")")
    fi

    if [ -z "$TOOLCHAIN_PATH" ]; then
        ANDROID_BUILD_FAIL+=("Please set the TOOLCHAIN_PATH environment variable")
        ANDROID_BUILD_FAIL+=("  (eg. \"/home/user/android/android-ndk-r25/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin\")")
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

    if [ ! -d "$ANDROID_STL_ROOT" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_STL_ROOT directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_STL_ROOT}")
    fi

    if [ -n "${ANDROID_LIBC_ROOT}" ] && [ ! -d "${ANDROID_LIBC_ROOT}" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_LIBC_ROOT directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_LIBC_ROOT}")
    fi

    if [ ! -d "${ANDROID_BUILD_TOOLCHAIN}" ]; then
        ANDROID_BUILD_FAIL+=("The ANDROID_BUILD_TOOLCHAIN directory does not exist")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_TOOLCHAIN}")
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
    export ANDROID_BUILD_CC="${TOOLCHAIN_PATH}/${TOOLCHAIN_COMP}-clang"
    export ANDROID_BUILD_CXX="${TOOLCHAIN_PATH}/${TOOLCHAIN_COMP}-clang++"
    # Since NDK r22 the "platforms" dir got removed and the default linker is LLD
    if [ -d "${ANDROID_NDK_ROOT}/platforms" ]; then
       export ANDROID_BUILD_LD="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ld"
    else
       export ANDROID_BUILD_LD="${TOOLCHAIN_PATH}/ld"
    fi
    # Since NDK r24 this binary was removed due to LLVM being now the default
    if [ ! -x "${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-as" ]; then
        export ANDROID_BUILD_AS="${TOOLCHAIN_PATH}/llvm-as"
    else
        export ANDROID_BUILD_AS="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-as"
    fi
    # Since NDK r23 those binaries were removed due to LLVM being now the default
    if [ ! -x "${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ar" ]; then
        export ANDROID_BUILD_AR="${TOOLCHAIN_PATH}/llvm-ar"
        export ANDROID_BUILD_RANLIB="${TOOLCHAIN_PATH}/llvm-ranlib"
        export ANDROID_BUILD_STRIP="${TOOLCHAIN_PATH}/llvm-strip"
    else
        export ANDROID_BUILD_AR="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ar"
        export ANDROID_BUILD_RANLIB="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ranlib"
        export ANDROID_BUILD_STRIP="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-strip"
    fi

    if [ ! -x "${ANDROID_BUILD_CC}" ]; then
        ANDROID_BUILD_FAIL+=("The CC binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_CC}")
    fi

    if [ ! -x "${ANDROID_BUILD_CXX}" ]; then
        ANDROID_BUILD_FAIL+=("The CXX binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_CXX}")
    fi

    if [ ! -x "${ANDROID_BUILD_LD}" ]; then
        ANDROID_BUILD_FAIL+=("The LD binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_LD}")
    fi

    if [ ! -x "${ANDROID_BUILD_AS}" ]; then
        ANDROID_BUILD_FAIL+=("The AS binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_AS}")
    fi

    if [ ! -x "${ANDROID_BUILD_AR}" ]; then
        ANDROID_BUILD_FAIL+=("The AR binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_AR}")
    fi

    if [ ! -x "${ANDROID_BUILD_RANLIB}" ]; then
        ANDROID_BUILD_FAIL+=("The RANLIB binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_RANLIB}")
    fi

    if [ ! -x "${ANDROID_BUILD_STRIP}" ]; then
        ANDROID_BUILD_FAIL+=("The STRIP binary does not exist or is not executable")
        ANDROID_BUILD_FAIL+=("  ${ANDROID_BUILD_STRIP}")
    fi

    ANDROID_BUILD_OPTS+=("TOOLCHAIN=${ANDROID_BUILD_TOOLCHAIN}")
    ANDROID_BUILD_OPTS+=("CC=${ANDROID_BUILD_CC}")
    ANDROID_BUILD_OPTS+=("CXX=${ANDROID_BUILD_CXX}")
    ANDROID_BUILD_OPTS+=("LD=${ANDROID_BUILD_LD}")
    ANDROID_BUILD_OPTS+=("AS=${ANDROID_BUILD_AS}")
    ANDROID_BUILD_OPTS+=("AR=${ANDROID_BUILD_AR}")
    ANDROID_BUILD_OPTS+=("RANLIB=${ANDROID_BUILD_RANLIB}")
    ANDROID_BUILD_OPTS+=("STRIP=${ANDROID_BUILD_STRIP}")

    android_build_check_fail
}

# Set the ANDROID_BUILD_OPTS variable to a bash array of configure options
function android_build_opts {
    ANDROID_BUILD_OPTS=()

    _android_build_opts_process_binaries

    # Since NDK r23 we don't need -lgcc due to LLVM being now the default
    if [ ! -x "${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-ar" ]; then
        export ANDROID_BUILD_LIBS="-lc -ldl -lm -llog -lc++_shared"
    else
        export ANDROID_BUILD_LIBS="-lc -lgcc -ldl -lm -llog -lc++_shared"
    fi

    export ANDROID_BUILD_LDFLAGS="-L${ANDROID_BUILD_PREFIX}/lib"
    if [ -n "${ANDROID_LIBC_ROOT}" ] ; then
        ANDROID_BUILD_LDFLAGS+=" -L${ANDROID_LIBC_ROOT}"
    fi
    ANDROID_BUILD_LDFLAGS+=" -L${ANDROID_STL_ROOT}"

    export ANDROID_BUILD_CFLAGS+=" -D_GNU_SOURCE -D_REENTRANT -D_THREAD_SAFE"
    export ANDROID_BUILD_CPPFLAGS+=" -I${ANDROID_BUILD_PREFIX}/include"

    if [ "${NDK_NUMBER}" -ge 2400 ] ; then
        if [ "${BUILD_ARCH}" = "arm64" ] ; then
            export ANDROID_BUILD_CXXFLAGS+=" -mno-outline-atomics"
        fi
    fi

    ANDROID_BUILD_OPTS+=("CFLAGS=${ANDROID_BUILD_CFLAGS} ${ANDROID_BUILD_EXTRA_CFLAGS}")
    ANDROID_BUILD_OPTS+=("CPPFLAGS=${ANDROID_BUILD_CPPFLAGS} ${ANDROID_BUILD_EXTRA_CPPFLAGS}")
    ANDROID_BUILD_OPTS+=("CXXFLAGS=${ANDROID_BUILD_CXXFLAGS} ${ANDROID_BUILD_EXTRA_CXXFLAGS}")
    ANDROID_BUILD_OPTS+=("LDFLAGS=${ANDROID_BUILD_LDFLAGS} ${ANDROID_BUILD_EXTRA_LDFLAGS}")
    ANDROID_BUILD_OPTS+=("LIBS=${ANDROID_BUILD_LIBS} ${ANDROID_BUILD_EXTRA_LIBS}")

    ANDROID_BUILD_OPTS+=("PKG_CONFIG_LIBDIR=${ANDROID_NDK_ROOT}/prebuilt/${ANDROID_BUILD_PLATFORM}/lib/pkgconfig")
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

    local readelf="${TOOLCHAIN_PATH}/${TOOLCHAIN_HOST}-readelf"
    if command -v "${readelf}" >/dev/null 2>&1 ; then
        export ANDROID_BUILD_READELF="${readelf}"
    elif command -v readelf >/dev/null 2>&1 ; then
        export ANDROID_BUILD_READELF="readelf"
    elif command -v greadelf >/dev/null 2>&1 ; then
        export ANDROID_BUILD_READELF="greadelf"
    else
        ANDROID_BUILD_FAIL+=("Could not find any of readelf, greadelf, or ${readelf}")
    fi
    android_build_check_fail

    local elfoutput
    elfoutput=$(LC_ALL=C ${ANDROID_BUILD_READELF} -d "${sofile}")

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

    for dep_soname in "$@" ; do
        local dep_sofile="${ANDROID_BUILD_PREFIX}/lib/${dep_soname}"
        if [ ! -f "${dep_sofile}" ]; then
            ANDROID_BUILD_FAIL+=("Found no library named ${dep_soname}")
            ANDROID_BUILD_FAIL+=("  ${dep_sofile}")
        elif [[ $elfoutput != *"library: [${dep_soname}]"* ]]; then
            ANDROID_BUILD_FAIL+=("Library ${soname} was expected to be linked to library with soname:")
            ANDROID_BUILD_FAIL+=("  ${dep_soname}")
        fi
    done

    android_build_check_fail
}

function android_show_configure_opts {
    local tag=$1
    shift
    android_build_trace "./configure options to build '${tag}':"
    for opt in "$@"; do
        echo "  > ${opt}"
    done
    echo ""
}

# Initialize env variable XXX_ROOT, given dependency name "xxx".
# If XXX_ROOT is not set:
#    If ${PROJECT_ROOT}/../xxx exists
#        set XXX_ROOT with it.
#    Else
#        set XXX_ROOT with ${ANDROID_DEPENDENCIES_DIR}/xxx.
# Else
#    Verify that folder XXX_ROOT exists.
function android_init_dependency_root {
    local lib_name
    lib_name="$1"
    local variable_name
    variable_name="$(echo "${lib_name}" | tr '[:lower:]' '[:upper:]')_ROOT"
    local variable_value
    variable_value="$(eval echo "\${${variable_name}}")"

    if [ -z "${PROJECT_ROOT}" ] ; then
        android_build_trace "Error: Variable PROJECT_ROOT is not set."
        exit 1
    fi
    if [ ! -d "${PROJECT_ROOT}" ] ; then
        android_build_trace "Error: Cannot find folder '${PROJECT_ROOT}'."
        exit 1
    fi

    if [ -z "${variable_value}" ] ; then
        if [ -d "${PROJECT_ROOT}/../${lib_name}" ] ; then
            eval "export ${variable_name}=\"$(cd "${PROJECT_ROOT}/../${lib_name}" && pwd)\""
        else
            eval "export ${variable_name}=\"${ANDROID_DEPENDENCIES_DIR}/${lib_name}\""
        fi
        variable_value="$(eval echo "\${${variable_name}}")"
    elif [ ! -d "${variable_value}" ] ; then
        android_build_trace "Error: Folder '${variable_value}' does not exist."
        exit 1
    fi

    android_build_trace "${variable_name}=${variable_value}"
}

function android_download_library {
    local tag="$1" ; shift
    local root="$1" ; shift
    local url="$1" ; shift
    local parent="$(dirname "${root}")"
    local archive="$(basename "${url}")"

    mkdir -p "${parent}"
    cd "${parent}"

    android_build_trace "Downloading ${tag} from '${url}' ..."
    rm -f "${archive}"
    wget -q "${url}"
    case "${archive}" in
        *."tar.gz" ) folder="$(basename "${archive}" ".tar.gz")" ;;
        *."tgz" )    folder="$(basename "${archive}" ".tgz")" ;;
        * ) android_build_trace "Unsupported extension for '${archive}'." ; exit 1 ;;
    esac
    android_build_trace "Extracting '${archive}' ..."
    tar -xzf "${archive}"
    if [ ! -d "${root}" ] ; then
	mv "${folder}" "${root}"
    fi
    android_build_trace "${tag} extracted under under '${root}'."
}

function android_clone_library {
    local tag="$1" ; shift
    local root="$1" ; shift
    local url="$1" ; shift
    local branch="$1" ; shift

    mkdir -p "$(dirname "${root}")"
    if [ -n "${branch}" ] ; then
        android_build_trace "Cloning '${url}' (branch '${branch}') under '${root}'."
        git clone --quiet --depth 1 -b "${branch}" "${url}" "${root}"
    else
        android_build_trace "Cloning '${url}' (default branch) under '${root}'."
        git clone --quiet --depth 1 "${url}" "${root}"
    fi
    ( cd "${root}" && git log --oneline -n 1)  || exit 1
}

# Caller must set CONFIG_OPTS[], before call.
function android_build_library {
    local tag=$1 ; shift
    local root=$1 ; shift

    android_build_trace "Cleaning library '${tag}'."
    (
        if [ -n "${ANDROID_BUILD_PREFIX}" ] && [ -d "${ANDROID_BUILD_PREFIX}" ] ; then
            # Remove *.la files as they might cause errors with cross compiled libraries
            find "${ANDROID_BUILD_PREFIX}" -name '*.la' -exec rm {} +
        fi

        cd "${root}" \
        && ( make clean || : ) \
        && rm -f config.status
    ) &> /dev/null

    android_build_trace "Building library '${tag}'."
    (
        set -e

        android_show_configure_opts "${tag}" "${CONFIG_OPTS[@]}"

        cd "${root}"
        if [ -e autogen.sh ]; then
            ./autogen.sh 2> /dev/null
        fi
        if [ -e buildconf ]; then
            ./buildconf 2> /dev/null
        fi
        if [ ! -e autogen.sh ] && [ ! -e buildconf ] && [ ! -e ./configure ] && [ -s ./configure.ac ] ; then
            libtoolize --copy --force && \
            aclocal -I . && \
            autoheader && \
            automake --add-missing --copy && \
            autoconf || \
            autoreconf -fiv
        fi

        ./configure "${CONFIG_OPTS[@]}"
        make -j 4
        make install
    )
}

########################################################################
# Initialization
########################################################################
# Get directory of current script (if not already set)
# This directory is also the basis for the build directories the get created.
if [ -z "$ANDROID_BUILD_DIR" ]; then
    export ANDROID_BUILD_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
fi

# Where to download our dependencies
export ANDROID_DEPENDENCIES_DIR="${ANDROID_DEPENDENCIES_DIR:-/tmp/tmp-deps}"

# Set up a variable to hold the global failure reasons, separated by newlines
# (Empty string indicates no failure)
ANDROID_BUILD_FAIL=()

########################################################################
# Sanity checks
########################################################################
case "${NDK_VERSION}" in
    "android-ndk-r"[0-9][0-9] ) : ;;
    "android-ndk-r"[0-9][0-9][a-z] ) : ;;
    "" ) android_build_trace "Variable NDK_VERSION not set." ; exit 1 ;;
    * ) android_build_trace "Invalid format for NDK_VERSION ('${NDK_VERSION}')" ; exit 1 ;;
esac

if [ -z "${ANDROID_NDK_ROOT}" ] ; then
    android_build_trace "ANDROID_NDK_ROOT not set !"
    exit 1
fi

########################################################################
# Compute NDK version into a numeric form:
#   android-ndk-r21e -> 2105
#   android-ndk-r25  -> 2500
########################################################################
export NDK_NUMBER="$(( $(echo "${NDK_VERSION}"|sed -e 's|android-ndk-r||g' -e 's|[a-z]||g') * 100 ))"
NDK_VERSION_LETTER="$(echo "${NDK_VERSION}"|sed -e 's|android-ndk-r[0-9][0-9]||g'|tr '[:lower:]' '[:upper:]')"
if [ -n "${NDK_VERSION_LETTER}" ] ; then
    NDK_NUMBER=$(( $(( NDK_NUMBER + $(printf '%d' \'"${NDK_VERSION_LETTER}") )) - 64 ))
fi
android_build_trace "Configured NDK_VERSION: ${NDK_VERSION} ($NDK_NUMBER)."

