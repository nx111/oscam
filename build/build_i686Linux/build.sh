#!/bin/sh
plat=i686_linux
plat_dir=build_i686Linux
TOOLCHAIN=i686-pc-linux-gnu
TOOLCHAIN_ROOT=i686-pc-linux-gnu
TOOCHAINFILE=toolchain-i686-pc-linux.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains

#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 

##############################################

if [ "$base" != "1" ]; then
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr/include\
	  -DOPENSSL_LIBRARIES=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr/lib\
	  -DOPENSSL_ROOT_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBPCSCDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DWITH_SSL=1\
	  -DSTATIC_LIBCRYPTO=1\
	  -DSTATIC_LIBSSL=1\
	  -DSTATIC_LIBUSB=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl
else
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sysroot/usr \
	  -DSTATIC_LIBUSB=1\
	  --clean-first\
	  -DWITH_SSL=0 \
	  -DHAVE_PCSC=0 \
	  -DWEBIF=1 $ROOT
fi

make STAGING_DIR=${TOOLCHAIN_STAGE}

##############################################

. $(dirname $builddir)/include/post_build.sh 
