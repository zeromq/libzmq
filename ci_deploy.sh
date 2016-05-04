#!/usr/bin/env bash

set -x
set -e

if [[ $TRAVIS_OS_NAME =~ (linux) ]]; then
    # Tell travis to deploy all files in dist
    mkdir dist
    export ZEROMQ41_DEPLOYMENT=dist/*
    # Move archives to dist
    mv *.tar.gz dist
    mv *.zip dist
    # Generate hash sums
    cd dist
    md5sum *.zip *.tar.gz > MD5SUMS
    sha1sum *.zip *.tar.gz > SHA1SUMS
    cd -
else
    export ZEROMQ4-1_DEPLOYMENT=""
fi
