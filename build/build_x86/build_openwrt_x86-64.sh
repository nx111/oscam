#!/bin/sh
plat=openwrt-x86_64
plat_dir=build_openwrt
Architecture=
libc=musl
machine=openwrt
TOOLCHAIN=x86_64-openwrt-linux
TOOLCHAIN_ROOT=toolchain-x86_64_gcc-7.4.0_musl
TOOCHAINFILE=toolchain-x86_64-openwrt.cmake
TOOLCHAIN_STAGE=/work/dreambox/toolchains/x86_64-openwrt-gcc-7.4.0
STAGING_DIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/bin
#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 
##############################################

if  [ "$buildtype" = "inline" ]; then
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH STAGING_DIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/bin \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/include \
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/include \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBPCSCDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DWITH_SSL=1\
	  -DSTATIC_LIBCRYPTO=1\
	  -DSTATIC_LIBSSL=1\
	  -DSTATIC_LIBUSB=1\
	  -DSTATIC_LIBPCSC=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl-inline
else
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH STAGING_DIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/bin \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/include\
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/usr/ \
	  -DWITH_SSL=0\
	  -DSTATIC_LIBCRYPTO=0\
	  -DSTATIC_LIBSSL=0\
	  -DSTATIC_LIBUSB=1\
	  -DSTATIC_LIBPCSC=0\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl
fi

make STAGING_DIR=${TOOLCHAIN_STAGE}

##############################################

. $(dirname $builddir)/include/post_build.sh 

