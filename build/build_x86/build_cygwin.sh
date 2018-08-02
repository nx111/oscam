#!/bin/sh
plat=cygwin
plat_dir=build_x86
machine=cygwin
TOOLCHAIN=i686-pc-cygwin
TOOLCHAIN_ROOT=i686-pc-cygwin
TOOCHAINFILE=toolchain-i386-cygwin.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains
#############################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

. $(dirname $builddir)/include/pre_build.sh 

##############################################

   LD_LIBRARY_PATH=$TOOLCHAINROOT/$TOOLCHAIN/lib \
   PATH=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE}\
	  -DCMAKE_LEGACY_CYGWIN_WIN32=1\
	  -DOPTIONAL_INCLUDE_DIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/$TOOLCHAIN/include\
	  -DOPENSSL_INCLUDE_DIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/$TOOLCHAIN/include\
	  -DLIBRTDIR=$TOOLCHAIN_STAGE/$TOOLCHAIN_ROOT/$TOOLCHAIN/ \
	  -DSTATIC_LIBCRYPTO=1\
	  -DSTATIC_LIBSSL=1\
	  -DWITH_SSL=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl-inline

LD_LIBRARY_PATH=$TOOLCHAINROOT/$TOOLCHAIN/lib \
make  STAGING_DIR=${TOOLCHAIN_STAGE}

##############################################

. $(dirname $builddir)/include/post_build.sh 
