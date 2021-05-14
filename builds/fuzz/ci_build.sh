#!/usr/bin/env bash
# used by oss-fuzz https://github.com/google/oss-fuzz/tree/master/projects/libzmq

set -e
set -x

cd "${SRC}/libsodium"
DO_NOT_UPDATE_CONFIG_SCRIPTS=1 ./autogen.sh
./configure --disable-shared --prefix=/install_prefix --disable-asm
make -j$(nproc) V=1 install DESTDIR=/tmp/zmq_install_dir

cd "${SRC}/libzmq"
./autogen.sh
export LDFLAGS+=" $(PKG_CONFIG_PATH=/tmp/zmq_install_dir/install_prefix/lib/pkgconfig pkg-config --static --libs --define-prefix libsodium)"
export CXXFLAGS+=" $(PKG_CONFIG_PATH=/tmp/zmq_install_dir/install_prefix/lib/pkgconfig pkg-config --static --cflags --define-prefix libsodium)"
./configure --disable-shared --prefix=/install_prefix --disable-perf --disable-curve-keygen PKG_CONFIG_PATH=/tmp/zmq_install_dir/install_prefix/lib/pkgconfig --with-libsodium=yes --with-fuzzing-installdir=fuzzers --with-fuzzing-engine=$LIB_FUZZING_ENGINE
make -j$(nproc) V=1 install DESTDIR=/tmp/zmq_install_dir

cd "${SRC}/libzmq-fuzz-corpora"
cp dictionaries/* /tmp/zmq_install_dir/install_prefix/fuzzers/
for t in test_*_seed_corpus; do
  zip -j --quiet /tmp/zmq_install_dir/install_prefix/fuzzers/${t}.zip ${t}/*
done

cp /tmp/zmq_install_dir/install_prefix/fuzzers/* "${OUT}"
