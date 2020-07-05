BUILD_DIR=`pwd`/build

if [[ -d ${BUILD_DIR} ]]; then
  rm -fr ${BUILD_DIR}
fi

mkdir -p ${BUILD_DIR}

SDK_ROOT="/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer"
export CPP="cpp"
export CXXCPP="cpp"
export CXX="/usr/bin/clang"
export CC="/usr/bin/clang"
export AR="/usr/bin/ar"
export AS="/usr/bin/as"
export LD="/usr/bin/ld"
export LDFLAGS="-lstdc++"
export LIBTOOL="/usr/bin/libtool"
export STRIP="/usr/bin/strip"
export RANLIB="/usr/bin/ranlib"

./autogen.sh &&
./configure --disable-dependency-tracking --enable-static --disable-shared --host=arm-apple-darwin --prefix=${BUILD_DIR} &&
make VERBOSE=1 -j5 ${CHECK}
# make install
# make clean
mkdir ${BUILD_DIR}/usr && cp -R include ${BUILD_DIR}/usr