FROM ubuntu:14.04
MAINTAINER Benjamin Henrion <zoobab@gmail.com>
 
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y -q
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y -q --force-yes tar git curl nano wget dialog net-tools build-essential vim emacs apt-utils file uuid-dev cmake asciidoc python autoconf automake libtool pkg-config xmlto sudo gettext apt-utils

RUN useradd -d /home/zmq -m -s /bin/bash zmq
RUN echo "zmq ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/zmq
RUN chmod 0440 /etc/sudoers.d/zmq

USER zmq
# install android-ndk
RUN cd ~ && wget -q http://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin -O android-ndk-r10e-linux-x86_64.bin && chmod +x android-ndk-r10e-linux-x86_64.bin
RUN cd ~ && ./android-ndk-r10e-linux-x86_64.bin
ENV ANDROID_NDK_ROOT /home/zmq/android-ndk-r10e
ENV TOOLCHAIN_NAME arm-linux-androideabi-4.9
ENV TOOLCHAIN_HOST arm-linux-androideabi
ENV TOOLCHAIN_PATH ${ANDROID_NDK_ROOT}/toolchains/${TOOLCHAIN_NAME}/prebuilt/linux-x86_64/bin
ENV TOOLCHAIN_ARCH arm
# build libzmq for android
RUN cd ~ && git clone --depth 1 https://github.com/zeromq/libzmq.git
RUN cd ~/libzmq/builds/android && ./build.sh
