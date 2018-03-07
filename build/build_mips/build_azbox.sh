#!/bin/sh
plat=azbox
plat_dir=build_mips
machine=azbox
TOOLCHAIN=mipsel-linux-gnu
TOOLCHAIN_ROOT=boardcom-stbgcc-4.8-1.5
TOOCHAINFILE=toolchain-mipsel-azbox.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains
OSCAM_TARGET=/PLUGINS/OpenXCAS/oscamCAS/oscam

#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 

##############################################

if  [ "$buildtype" = "inline" ]; then
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBPCSCDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DWITH_SSL=1\
	  -DSTATIC_LIBCRYPTO=1\
	  -DSTATIC_LIBSSL=1\
	  -DSTATIC_LIBUSB=1\
	  -DSTATIC_LIBPCSC=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl-inline
else
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBSSLDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBCRYPTODIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
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

