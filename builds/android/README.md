LIBZMQ ANDROID COMPILATION STEPS
================================
To launch the docker build:

    $ docker build .

To launch the android build, you have to first install the android-ndk first in your HOME directory:

    $ cd ~
    $ export ANDROID_NDK_VERSION="r10e"
    $ wget -q http://dl.google.com/android/ndk/android-ndk-${ANDROID_NDK_VERSION}-linux-x86_64.bin -O android-ndk-${ANDROID_NDK_VERSION}-linux-x86_64.bin
    $ chmod +x android-ndk-${ANDROID_NDK_VERSION}-linux-x86_64.bin
    $ ./android-ndk-r10e-linux-x86_64.bin
    $ export ANDROID_NDK_ROOT /home/zmq/android-ndk-r10e
    $ export TOOLCHAIN_NAME arm-linux-androideabi-4.9
    $ export TOOLCHAIN_HOST arm-linux-androideabi
    $ export TOOLCHAIN_PATH ${ANDROID_NDK_ROOT}/toolchains/${TOOLCHAIN_NAME}/prebuilt/linux-x86_64/bin
    $ export TOOLCHAIN_ARCH arm

Then you can launch the build:

    $ cd ~/libzmq/builds/android
    $ ./build.sh 
    Cloning into 'libsodium'...
    remote: Counting objects: 15246, done.
    remote: Compressing objects: 100% (182/182), done.
    Receiving objects:  16% (2440/15246)   
    [...]

A successful build should finish with the following message and give you back your shell prompt:

    [...]
    make[2]: Leaving directory '/tmp/android_build/arm-linux-androideabi-4.9/libzmq'
    make[1]: Leaving directory '/tmp/android_build/arm-linux-androideabi-4.9/libzmq'
    libzmq android build succeeded
    $ 

You will then be able to see libzmq.so compiled in the prefix/ directory:

    $ cd ~/libzmq/builds/android/prefix/arm-linux-androideabi-4.9/lib
    $ ls
    libsodium.a  libsodium.la  libsodium.so  libzmq.a  libzmq.la  libzmq.so  pkgconfig

You can then triple check that they are ARM libs:

    $ cd ~/libzmq/builds/android/prefix/arm-linux-androideabi-4.9/lib
    $ file libzmq.so
    libzmq.so: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /system/bin/linker, not stripped


COMPILE WITH DOCKERFILE
=======================

To launch the docker build with a tagged image as a result:

    $ cd ~/libzmq/builds/android
    $ docker build -t libzmq-android:`date +"%y%m%d-%H%M%S"` .
    $ docker build -t libzmq-android:latest .

If it is successful, it will end by "libzmq android build succeeded" followed by the ContainerID "e53db616aff4":

    [...]
    make[2]: Leaving directory `/tmp/android_build/arm-linux-androideabi-4.9/libzmq'
    make[1]: Leaving directory `/tmp/android_build/arm-linux-androideabi-4.9/libzmq'
    libzmq android build succeeded
    ---> e53db616aff4
    Removing intermediate container 8a5f3e34f3da
    Successfully built e53db616aff4
    $

    $ docker images
    REPOSITORY          TAG                 IMAGE ID            CREATED             VIRTUAL SIZE
    libzmq-android      151218-101411       e53db616aff4        18 hours ago        5.495 GB

If you want to collect the artifacts on the build, you can specify a directory in your HOME directory, such as "$HOME/libzmq-android-bins" for example:
    
    $ mkdir -pv $HOME/libzmq-android-bins
    $ docker run -v $HOME/libzmq-android-bins:/data libzmq-android:latest "cp -v /home/zmq/libzmq/builds/android/prefix/arm-linux-androideabi-4.9/lib/* /data"
