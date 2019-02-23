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

    # Trigger source run on new tag on OBS.
    # We have to keep a release branch on the lastest tag, as it is
    # not possible to edit files on OBS with secure tokens, and it is not
    # possible to dynamically fetch the latest git tag either.
    if [ -n "${GH_TOKEN}" -a -n "${OBS_STABLE_TOKEN}" -a -n "${OBS_DRAFT_TOKEN}" ]; then
        TAG_SHA=$(curl -s -H "Authorization: token ${GH_TOKEN}" -X GET https://api.github.com/repos/zeromq/libzmq/git/refs/tags/${TRAVIS_TAG} | grep -o -P '(?<=sha":\s).*(?=,)')
        curl -H "Authorization: token ${GH_TOKEN}" -X DELETE https://api.github.com/repos/zeromq/libzmq/git/refs/heads/latest_release
        curl -H "Authorization: token ${GH_TOKEN}" -X POST --data "{\"ref\":\"refs/heads/latest_release\",\"sha\":${TAG_SHA}}" https://api.github.com/repos/zeromq/libzmq/git/refs
        sleep 2 # try to avoid races if Github is slow
        curl -H "Authorization: Token ${OBS_STABLE_TOKEN}" -X POST https://api.opensuse.org/trigger/runservice
        curl -H "Authorization: Token ${OBS_DRAFT_TOKEN}" -X POST https://api.opensuse.org/trigger/runservice
    fi
else
    export LIBZMQ_DEPLOYMENT=""
fi
