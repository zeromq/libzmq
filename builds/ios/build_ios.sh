#!/bin/sh
# This is a first attempt to create a script to libzmq for iOS >= 13.5, including arm64
# inspired on https://raw.githubusercontent.com/drewcrawford/libzmq-ios/master/libzmq.sh

set -e
LIBNAME="libzmq.a"
ARCHS=${ARCHS:-"armv7 armv7s arm64 x86_64"}
DEVELOPER=$(xcode-select -print-path)
LIPO=$(xcrun -sdk iphoneos -find lipo)
SCRIPTDIR=$( (cd -P $(dirname $0) && pwd) )
DISTLIBDIR="${SCRIPTDIR}/lib"
DSTDIR=${SCRIPTDIR}
BUILDDIR="${DSTDIR}/libzmq_build"
DISTDIR="${DSTDIR}/libzmq_dist"
LIBDIR=$(dirname $(dirname ${SCRIPTDIR}))
SDK=$(xcodebuild -showsdks \
    | grep iphoneos | sort | tail -n 1 | awk '{print substr($NF, 9)}'
    )
IOS_VERSION_MIN=8.0
OTHER_LDFLAGS=""
OTHER_CFLAGS="-Os -Qunused-arguments"
# Enable Bitcode
OTHER_CPPFLAGS="-Os -fembed-bitcode"
OTHER_CXXFLAGS="-Os"

${LIBDIR}/autogen.sh
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

    echo "Configuring for ${ARCH}..."
    set +e
    cd ${LIBDIR} 
    set -e
    ${LIBDIR}/configure \
	--prefix=${BUILDARCHDIR} \
	--disable-shared \
	--enable-static \
	--host=${HOST}

    echo "Building ${LIBNAME} for ${ARCH}..."
    cd ${LIBDIR}
    
    make -j8 
    make install
	make clean

done

mkdir -p ${DISTLIBDIR}
for ARCH in $ARCHS
do
	LIBPATH="$BUILDDIR/$ARCH/lib/${LIBNAME}"
	LIBLIST+=" -arch ${ARCH} ${LIBPATH}"
done

set +e

${LIPO} -create ${LIBLIST} -output ${DISTLIBDIR}/${LIBNAME}

echo "Done !"

