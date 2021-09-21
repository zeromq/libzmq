#!/usr/bin/env bash

set -x

mkdir tmp
BUILD_PREFIX=$PWD/tmp

source ../../config.sh
set_config_opts

CONFIG_OPTS+=("--enable-code-coverage")

# Build, check, and install from local source
( cd ../..; ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make VERBOSE=1 -j5 check-code-coverage CODE_COVERAGE_OUTPUT_FILE=lcov.info CODE_COVERAGE_OUTPUT_DIRECTORY=coverage) || exit 1
