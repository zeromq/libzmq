#!/usr/bin/env bash

set -x

mkdir tmp
BUILD_PREFIX=$PWD/tmp

source ../../config.sh
set_config_opts

CONFIG_OPTS+=("--enable-code-coverage")

pip install --user cpp-coveralls

# Build, check, and install from local source
( cd ../..; ./autogen.sh && ./configure "${CONFIG_OPTS[@]}" && make VERBOSE=1 -j5 check && coveralls --include src --exclude src/tweetnacl.c --exclude src/tweetnacl.h --build-root . --gcov-options '\-lp') || exit 1
