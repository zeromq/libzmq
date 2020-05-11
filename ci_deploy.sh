#!/usr/bin/env bash

# do NOT set -x or it will log the secret tokens!
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

    # Trigger source run on new tag on OBS. The latest tag will be fetched.
    if [ -n "${OBS_STABLE_TOKEN}" ]; then
        curl -H "Authorization: Token ${OBS_STABLE_TOKEN}" -X POST https://api.opensuse.org/trigger/runservice
    fi
    if [ -n "${OBS_DRAFT_TOKEN}" ]; then
        curl -H "Authorization: Token ${OBS_DRAFT_TOKEN}" -X POST https://api.opensuse.org/trigger/runservice
    fi
else
    export LIBZMQ_DEPLOYMENT=""
fi
