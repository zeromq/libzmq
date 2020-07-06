#!/bin/sh
# A script to download and build libzmq for iOS, including arm64
# inspired on https://raw.githubusercontent.com/drewcrawford/libzmq-ios/master/libzmq.sh

ARCHS=${ARCHS:-"armv7 armv7s arm64 x86_64"}
DEVELOPER=$(xcode-select -print-path)
LIPO=$(xcrun -sdk iphoneos -find lipo)
#LIPO=lipo
# Script's directory
SCRIPTDIR=$( (cd -P $(dirname $0) && pwd) )
DISTLIBDIR="${SCRIPTDIR}/lib"
# Destination directory for build and install
DSTDIR=${SCRIPTDIR}
BUILDDIR="${DSTDIR}/libzmq_build"
DISTDIR="${DSTDIR}/libzmq_dist"
LIBDIR=$(dirname ${SCRIPTDIR})
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

# if [[ -d ${BUILD_DIR} ]]; then
#   rm -fr ${BUILD_DIR}
# fi

# mkdir -p ${BUILD_DIR}

# SDK_ROOT="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer"
# export CPP="cpp"
# export CXXCPP="cpp"
# export CXX="/usr/bin/clang"
# export CC="/usr/bin/clang"
# export AR="/usr/bin/ar"
# export AS="/usr/bin/as"
# export LD="/usr/bin/ld"
# export LDFLAGS="-lstdc++"
# export LIBTOOL="/usr/bin/libtool"
# export STRIP="/usr/bin/strip"
# export RANLIB="/usr/bin/ranlib"

# ./autogen.sh &&
# ./configure --disable-dependency-tracking --enable-static --disable-shared --host=arm-apple-darwin --prefix=${BUILD_DIR} &&
# make VERBOSE=1 -j5 ${CHECK}
# # make install
# # make clean
# mkdir ${BUILD_DIR}/usr && cp -R include ${BUILD_DIR}/usr

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

        i386)
	    PLATFORM="iPhoneSimulator"
	    HOST="${ARCH}-apple-darwin"
	    export BASEDIR="${DEVELOPER}/Platforms/${PLATFORM}.platform/Developer"
	    export ISDKROOT="${BASEDIR}/SDKs/${PLATFORM}${SDK}.sdk"
	    export CXXFLAGS="${OTHER_CXXFLAGS}"
	    export CPPFLAGS="-m32 -arch ${ARCH} -isysroot ${ISDKROOT} -mios-version-min=${IOS_VERSION_MIN} ${OTHER_CPPFLAGS}"
	    export LDFLAGS="-m32 -arch ${ARCH} ${OTHER_LDFLAGS}"
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

# # Copy headers and generate a single fat library file
# mkdir -p ${DISTLIBDIR}
# ${LIPO} -create ${LIBLIST} -output ${DISTLIBDIR}/${LIBNAME}
# for ARCH in $ARCHS
# do
#     cp -R $BUILDDIR/$ARCH/include ${DISTDIR}
#     break
# done

echo ${DISTLIBDIR}