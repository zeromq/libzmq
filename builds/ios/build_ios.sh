#!/bin/sh
# This is a first attempt to create a script to libzmq for iOS >= 13.5, including arm64
# inspired on https://raw.githubusercontent.com/drewcrawford/libzmq-ios/master/libzmq.sh

ARCHS=${ARCHS:-"armv7 armv7s arm64 x86_64"}
DEVELOPER=$(xcode-select -print-path)
SCRIPTDIR=$( (cd -P $(dirname $0) && pwd) )
DISTLIBDIR="${SCRIPTDIR}/lib"
DSTDIR=${SCRIPTDIR}
BUILDDIR="${DSTDIR}/libzmq_build"
DISTDIR="${DSTDIR}/libzmq_dist"
LIBDIR=$(dirname $(dirname ${SCRIPTDIR}))
${LIBDIR}/autogen.sh

# http://libwebp.webm.googlecode.com/git/iosbuild.sh
# Extract the latest SDK version from the final field of the form: iphoneosX.Y
SDK=$(xcodebuild -showsdks \
    | grep iphoneos | sort | tail -n 1 | awk '{print substr($NF, 9)}'
    )

IOS_VERSION_MIN=8.0
OTHER_LDFLAGS=""
OTHER_CFLAGS="-Os -Qunused-arguments"
OTHER_CXXFLAGS="-Os"

for ARCH in $ARCHS
do
    BUILDARCHDIR="$BUILDDIR/$ARCH"
    mkdir -p ${BUILDARCHDIR}

    case ${ARCH} in
        armv7)
	    PLATFORM="iPhoneOS"
	    HOST="${ARCH}-apple-darwin"
	    export BASEDIR="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	    export ISDKROOT="${BASEDIR}/SDKs/${PLATFORM}${SDK}.sdk"
	    export CXXFLAGS="${OTHER_CXXFLAGS}"
	    export CPPFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} -mios-version-min=${IOS_VERSION_MIN} ${OTHER_CPPFLAGS}"
	    export LDFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} ${OTHER_LDFLAGS}"
            ;;

        armv7s)
	    PLATFORM="iPhoneOS"
	    HOST="${ARCH}-apple-darwin"
	    export BASEDIR="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	    export ISDKROOT="${BASEDIR}/SDKs/${PLATFORM}${SDK}.sdk"
	    export CXXFLAGS="${OTHER_CXXFLAGS}"
	    export CPPFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} -mios-version-min=${IOS_VERSION_MIN} ${OTHER_CPPFLAGS}"
	    export LDFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} ${OTHER_LDFLAGS}"
            ;;

        arm64)
	    PLATFORM="iPhoneOS"
	    HOST="arm-apple-darwin"
	    export BASEDIR="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	    export ISDKROOT="${BASEDIR}/SDKs/${PLATFORM}${SDK}.sdk"
	    export CXXFLAGS="${OTHER_CXXFLAGS}"
	    export CPPFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} -mios-version-min=${IOS_VERSION_MIN} ${OTHER_CPPFLAGS}"
	    export LDFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} ${OTHER_LDFLAGS}"
            ;;

        x86_64)
	    PLATFORM="iPhoneSimulator"
	    HOST="${ARCH}-apple-darwin"
	    export BASEDIR="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	    export ISDKROOT="${BASEDIR}/SDKs/${PLATFORM}${SDK}.sdk"
	    export CXXFLAGS="${OTHER_CXXFLAGS}"
	    export CPPFLAGS="-arch ${ARCH} -isysroot ${ISDKROOT} -mios-version-min=${IOS_VERSION_MIN} ${OTHER_CPPFLAGS}"
	    export LDFLAGS="-arch ${ARCH} ${OTHER_LDFLAGS}"
	    echo "LDFLAGS $LDFLAGS"
            ;;
        *)
	    echo "Unsupported architecture ${ARCH}"
	    exit 1
            ;;
    esac

    export PATH="${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/bin:${DEVELOPER}/Toolchains/XcodeDefault.xctoolchain/usr/sbin:$PATH"

    echo "Configuring for ${ARCH}..."
    set +e
    cd ${LIBDIR} 
    set -e
    ${LIBDIR}/configure \
	--prefix=${BUILDARCHDIR} \
	--disable-shared \
	--enable-static \
	--host=${HOST}\
	--with-libsodium=${LIBSODIUM_DIST}

    echo "Building ${LIBNAME} for ${ARCH}..."
    cd ${LIBDIR}
    
    make -j8 V=0
    make install

    LIBLIST+="${BUILDARCHDIR}/lib/${LIBNAME} "
done

echo "Done !"
echo ${LIBLIST}