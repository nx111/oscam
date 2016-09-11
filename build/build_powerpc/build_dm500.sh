#!/bin/sh
plat=powerpc
plat_dir=build_powerpc
machine=dm500
TOOLCHAIN=powerpc-tuxbox-linux-gnu
TOOLCHAIN_ROOT=powerpc-tuxbox-linux-gnu
TOOCHAINFILE=toolchain-powerpc-tuxbox.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains

#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 

##############################################

if [ "$base" != "1" ]; then
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/include\
	  -DOPENSSL_LIBRARIES=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/lib\
	  -DOPENSSL_ROOT_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DLIBPCSCDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DWITH_SSL=0 \
	  -DUSE_LIBCRYPTO=0\
	  -DSTATIC_LIBUSB=1\
	  -DSTATIC_LIBPCSC=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl
else
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  --clean-first\
	  -DSTATIC_LIBUSB=1\
	  -DWITH_SSL=0 \
	  -DHAVE_PCSC=0 \
	  -DWEBIF=1 $ROOT
fi

make STAGING_DIR=${TOOLCHAIN_STAGE}

##############################################

. $(dirname $builddir)/include/post_build.sh
