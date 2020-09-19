#!/usr/bin/env bash

set -x
set -e

if [ $BUILD_TYPE = "default" ]; then
    mkdir tmp
    BUILD_PREFIX=$PWD/tmp

    source config.sh
    set_config_opts

    # Build and check this project
    (
        ./autogen.sh &&
        ./configure "${CONFIG_OPTS[@]}" &&
        export DISTCHECK_CONFIGURE_FLAGS="${CONFIG_OPTS[@]}" &&
        make VERBOSE=1 -j5 ${CHECK}
    ) || exit 1
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
