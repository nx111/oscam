#!/bin/sh
plat=arm-android
plat_dir=build_arm
machine=android
TOOLCHAIN=arm-linux-androideabi
TOOLCHAIN_ROOT=arm-linux-androideabi-4.9
TOOCHAINFILE=toolchain-arm-android.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains

#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh

##############################################
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr/include\
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr \
	  -DLIBPCSCDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr \
	  -DWITH_SSL=0\
	  -DSTATIC_LIBSSL=1\
	  -DSTATIC_LIBUSB=1\
	  -DSTATIC_LIBPCSC=1\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-inline

make STAGING_DIR=${TOOLCHAIN_STAGE} LIB_PTHREAD=  ANDROID_NDK=1 \
     CFLAGS="-I${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr/include:${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr/include/openssl"

##############################################

. $(dirname $builddir)/include/post_build.sh 

