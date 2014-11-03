#!/usr/bin/env bash

if [ $BUILD_TYPE == "default" ]; then
    #   Build required projects first

    #   libsodium
    git clone git://github.com/jedisct1/libsodium.git
    ( cd libsodium; ./autogen.sh; ./configure; make check; sudo make install; sudo ldconfig )

    #   Build and check this project
    ./autogen.sh && ./configure --with-libsodium=yes && make && make check
    sudo make install
else
    cd ./builds/${BUILD_TYPE} && ./ci_build.sh
fi
