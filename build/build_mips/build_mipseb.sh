#!/bin/sh
plat=mipseb
plat_dir=build_mips
machine=
TOOLCHAIN=mips-linux-gnu
TOOLCHAIN_ROOT=boardcom-stbgcc-4.8-1.5
TOOCHAINFILE=toolchain-mips-tuxbox.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains

#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 
##############################################

if [ "$base" != "1" ]; then
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DOPTIONAL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DOPENSSL_INCLUDE_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/include\
	  -DOPENSSL_LIBRARIES=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/lib\
	  -DOPENSSL_ROOT_DIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr/ \
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
   feature=-pcsc-ssl
else
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN/sys-root/usr \
	  -DSTATIC_LIBUSB=1\
	  --clean-first\
	  -DWITH_SSL=0 \
	  -DHAVE_PCSC=0 \
	  -DWEBIF=1 $ROOT
fi

make STAGING_DIR=${TOOLCHAIN_STAGE}

##############################################

. $(dirname $builddir)/include/post_build.sh 

