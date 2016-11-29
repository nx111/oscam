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
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/${TOOCHAINFILE} $ROOT
make LIB_PTHREAD=  ANDROID_NDK=1 \
     CFLAGS=-I${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/sysroot/usr/include

##############################################

. $(dirname $builddir)/include/post_build.sh 

