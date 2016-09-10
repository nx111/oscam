#!/bin/sh
plat=cygwin
plat_dir=build_cygwin
TOOLCHAIN=i686-pc-cygwin

#TOOLCHAINROOT=/work/dreambox/toolchains

##############################################################
curdir=`pwd`
builddir=`cd $(dirname $0);pwd`

[ -f $curdir/oscam.c -a -f $curdir/module-dvbapi.c ] && OSCAM_SRC=$curdir

if [ "${OSCAM_SRC}" != "" -a -f ${OSCAM_SRC}/oscam.c ]; then
	ROOT=$(cd ${OSCAM_SRC};pwd)
elif [ -f $(dirname $(dirname $builddir))/oscam.c ]; then
	ROOT=$(dirname $(dirname $builddir))
else
	echo "Not found oscam source directory! Please set OSCAM_SRC environment value..."
	cd $curdir
	exit
fi

#### parse option ########3
for op in "$@"; do
   [ "$op" = "-debug" ] && debug=1
   [ "$op" = "-base" ] && base=1
done

# fix config.sh for subverison changed to git
if [ -f $ROOT/config.sh ]; then
	cp $ROOT/config.sh $ROOT/config.sh.orig
	sed -e "s/^[[:space:]]*(svnversion .*/\
		revision=\`(svnversion -n . 2>\/dev\/null || printf 0) | sed \'s\/.*:\/\/; s\/[^0-9]*$\/\/; s\/^$\/0\/'\`\n\
\n\
		if [ \"\$revision\" = \"\" -o \"\$revision\" = \"0\" ]; then\n\
			git log  | grep git-svn-id | sed -n 1p | cut -d@ -f2 | cut -d' ' -f1\n\
		else\n\
			echo \$revision\n\
		fi\n\
/" -i $ROOT/config.sh

fi

[ -d $ROOT/build/.tmp ] || mkdir -p $ROOT/build/.tmp
rm -rf $ROOT/build/.tmp/*

[ "$TOOLCHAINROOT" = "" ] && TOOLCHAINROOT=$(dirname $ROOT)/toolchains
if [ ! -f $TOOLCHAINROOT/$TOOLCHAIN/bin/$TOOLCHAIN-gcc ]; then
	echo "Not found $TOOLCHAIN-gcc..."
	exit -1
fi
##################################################################
cd $ROOT/build/.tmp
[ -f $ROOT/config.h ] && cp $ROOT/config.h $ROOT/config.h.orig
if [ "$base" != "1" ]; then
   LD_LIBRARY_PATH=$TOOLCHAINROOT/$TOOLCHAIN/lib \
   PATH=$TOOLCHAINROOT/$TOOLCHAIN/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/toolchain-i386-cygwin.cmake\
	  -DCMAKE_LEGACY_CYGWIN_WIN32=1\
	  -DOPTIONAL_INCLUDE_DIR=$TOOLCHAINROOT/$TOOLCHAIN/$TOOLCHAIN/include\
	  -DOPENSSL_INCLUDE_DIR=$TOOLCHAINROOT/$TOOLCHAIN/$TOOLCHAIN/include\
	  -DOPENSSL_LIBRARIES=$TOOLCHAINROOT/$TOOLCHAIN/$TOOLCHAIN/lib\
	  -DOPENSSL_ROOT_DIR=$TOOLCHAINROOT/$TOOLCHAIN/$TOOLCHAIN\
	  -DLIBRTDIR=$TOOLCHAINROOT/$TOOLCHAIN/$TOOLCHAIN \
	  -DWITH_SSL=1\
	  -DSTATIC_LIBUSB=1\
	  --clean-first\
	  -DWEBIF=1 $ROOT
   feature=-pcsc-ssl
else
   LD_LIBRARY_PATH=$TOOLCHAINROOT/$TOOLCHAIN/lib \
   PATH=$TOOLCHAINROOT/$TOOLCHAIN/bin:$PATH \
   cmake  -DCMAKE_TOOLCHAIN_FILE=$ROOT/toolchains/toolchain-i386-cygwin.cmake \
	  -DLIBRTDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DLIBUSBDIR=${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/$TOOLCHAIN \
	  -DSTATIC_LIBUSB=1\
	  --clean-first\
	  -DWITH_SSL=0 \
	  -DHAVE_PCSC=0 \
	  -DWEBIF=1 $ROOT
fi

LD_LIBRARY_PATH=$TOOLCHAINROOT/$TOOLCHAIN/lib \
make
[ -f $ROOT/config.h.orig ] && mv $ROOT/config.h.orig $ROOT/config.h

[ -d ${builddir}/image ] || mkdir ${builddir}/image
cp $ROOT/build/.tmp/oscam.exe ${builddir}/image/
##################################################################
svnver=`$ROOT/config.sh --oscam-revision`
[ -f $ROOT/config.sh.orig ] && mv $ROOT/config.sh.orig $ROOT/config.sh


cd ${builddir}/image
if [ $# -ge 1 -a "$1" = "-debug" ]; then
	compile_time=$(date +%Y%m%d%H%M)D
else
	compile_time=$(date +%Y%m%d)
fi
tar czf $(dirname $builddir)/oscam-${plat}-r${svnver}${feature}-nx111-${compile_time}.tar.gz *

rm -rf $ROOT/build/.tmp/*
cd $curdir
