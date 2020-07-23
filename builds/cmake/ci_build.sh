#!/usr/bin/env bash

set -x -e

cd ../..

# always install custom builds from dist
# to make sure that `make dist` doesn't omit any files required to build & test
if [ -z "$DO_CLANG_FORMAT_CHECK" -a -z "$CLANG_TIDY" ]; then
    ./autogen.sh
    ./configure
    make -j5 dist-gzip
    V=$(./version.sh)
    tar -xzf zeromq-$V.tar.gz
    cd zeromq-$V
fi

mkdir tmp || true
BUILD_PREFIX=$PWD/tmp

CONFIG_OPTS=()
CONFIG_OPTS+=("CFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CPPFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("CXXFLAGS=-I${BUILD_PREFIX}/include")
CONFIG_OPTS+=("LDFLAGS=-L${BUILD_PREFIX}/lib")
CONFIG_OPTS+=("PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig")

CMAKE_OPTS=()
CMAKE_OPTS+=("-DCMAKE_INSTALL_PREFIX:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_PREFIX_PATH:PATH=${BUILD_PREFIX}")
CMAKE_OPTS+=("-DCMAKE_LIBRARY_PATH:PATH=${BUILD_PREFIX}/lib")
CMAKE_OPTS+=("-DCMAKE_INCLUDE_PATH:PATH=${BUILD_PREFIX}/include")
CMAKE_OPTS+=("-DENABLE_CAPSH=ON")

if [ "$CLANG_FORMAT" != "" ] ; then
    CMAKE_OPTS+=("-DCLANG_FORMAT=${CLANG_FORMAT}")
fi

if [ -z $CURVE ]; then
    CMAKE_OPTS+=("-DENABLE_CURVE=OFF")
elif [ $CURVE == "libsodium" ]; then
    CMAKE_OPTS+=("-DWITH_LIBSODIUM=ON")

    if ! ((command -v dpkg-query >/dev/null 2>&1 && dpkg-query --list libsodium-dev >/dev/null 2>&1) || \
            (command -v brew >/dev/null 2>&1 && brew ls --versions libsodium >/dev/null 2>&1)); then
        git clone --depth 1 -b stable git://github.com/jedisct1/libsodium.git
        ( cd libsodium; ./autogen.sh; ./configure --prefix=$BUILD_PREFIX; make install)
    fi
fi

CMAKE_PREFIXES=()
MAKE_PREFIXES=()
PARALLEL_MAKE_OPT="-j5"
if [ -n "$CLANG_TIDY" ] ; then
    CMAKE_OPTS+=("-DCMAKE_BUILD_TYPE=Debug") # do a debug build to avoid unused variable warnings with assertions, and to speed up build
    CMAKE_OPTS+=("-DCMAKE_CXX_CLANG_TIDY:STRING=${CLANG_TIDY}")
    if [ -n ${SONARCLOUD_BUILD_WRAPPER_PATH} ] ; then
        MAKE_PREFIXES+=("${SONARCLOUD_BUILD_WRAPPER_PATH}build-wrapper-linux-x86-64")
        MAKE_PREFIXES+=("--out-dir")
        MAKE_PREFIXES+=("${TRAVIS_BUILD_DIR}/bw-output")
        
    fi
    CMAKE_PREFIXES+=("scan-build-10")
    MAKE_PREFIXES+=("scan-build-10")
    MAKE_PREFIXES+=("-plist-html")
    SCAN_BUILD_OUTPUT="$(pwd)/scan-build-report"
    MAKE_PREFIXES+=("-o ${SCAN_BUILD_OUTPUT}")
    # TODO this does not work with sonarcloud.io as it misses the sonar-cxx plugin
    #MAKE_PREFIXES+=("-plist")
    IFS="/" read -ra GITHUB_USER <<< "${TRAVIS_REPO_SLUG}"
    PARALLEL_MAKE_OPT=""
fi

# Build, check, and install from local source
mkdir build_cmake
cd build_cmake
if [ "$DO_CLANG_FORMAT_CHECK" = "1" ] ; then
    if ! ( PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig cmake "${CMAKE_OPTS[@]}" .. && make clang-format-check) ; then
        make clang-format-diff
        exit 1
    fi
else
    if [ -n "$CLANG_TIDY" ] ; then
        ${CLANG_TIDY} -explain-config
    fi

    export CTEST_OUTPUT_ON_FAILURE=1
    PKG_CONFIG_PATH=${BUILD_PREFIX}/lib/pkgconfig ${CMAKE_PREFIXES[@]} cmake "${CMAKE_OPTS[@]}" ..
    ${MAKE_PREFIXES[@]} make ${PARALLEL_MAKE_OPT} all VERBOSE=1 | tee clang-tidy-report
    
    if [ -n "${SONAR_SCANNER_CLI_PATH}" ] ; then
        find ${SCAN_BUILD_OUTPUT} || echo "WARNING: ${SCAN_BUILD_OUTPUT} does not exist"
    
        ${SONAR_SCANNER_CLI_PATH}sonar-scanner \
            -Dsonar.projectKey=${GITHUB_USER}-libzmq \
            -Dsonar.organization=${GITHUB_USER}-github \
            -Dsonar.projectBaseDir=.. \
            -Dsonar.sources=${TRAVIS_BUILD_DIR}/include,${TRAVIS_BUILD_DIR}/src,${TRAVIS_BUILD_DIR}/tests,${TRAVIS_BUILD_DIR}/unittests \
            -Dsonar.cfamily.build-wrapper-output=${TRAVIS_BUILD_DIR}/bw-output \
            -Dsonar.host.url=https://sonarcloud.io \
            -Dsonar.login=${SONARQUBE_TOKEN}

            # TODO this does not work with sonarcloud.io as it misses the sonar-cxx plugin
            # -Dsonar.cxx.clangtidy.reportPath=clang-tidy-report \
            # -Dsonar.cxx.clangsa.reportPath=*.plist \
            
    fi

    make install
    make ${PARALLEL_MAKE_OPT} test ARGS="-V"
fi
