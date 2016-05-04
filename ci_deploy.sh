#!/usr/bin/env bash

set -x
set -e

if [[ $BUILD_TYPE == "default" && $CURVE == "libsodium" && -z $DRAFT ]]; then
    # Tell travis to deploy all files in dist
    mkdir dist
    export LIBZMQ_DEPLOYMENT=dist/*
    # Move archives to dist
    mv *.tar.gz dist
    mv *.zip dist
    # Generate hash sums
    cd dist
    md5sum *.zip *.tar.gz > MD5SUMS
    sha1sum *.zip *.tar.gz > SHA1SUMS
    cd -
else
    export LIBZMQ_DEPLOYMENT=""
fi
