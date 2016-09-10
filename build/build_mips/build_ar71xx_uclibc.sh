#!/bin/sh
plat=ar71xx
plat_dir=build_mips
libc=uClibc
machine=openwrt
TOOLCHAIN=mips-openwrt-linux
TOOLCHAIN_ROOT=mips_ar71xx_34kc_gcc-4.8-linaro_uClibc-0.9.33.2
TOOCHAINFILE=toolchain-mips-openwrt.cmake
#TOOLCHAIN_STAGE=/work/dreambox/toolchains

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

#### parse option ########
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

[ "${TOOLCHAIN_STAGE}" = "" ] && TOOLCHAIN_STAGE=$(dirname $ROOT)/toolchains
if [ ! -f ${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin/$TOOLCHAIN-gcc ]; then
	echo "Not found $TOOLCHAIN-gcc..."
	exit -1
fi
##################################################################
cd $ROOT/build/.tmp
[ -f $ROOT/config.h ] && cp $ROOT/config.h $ROOT/config.h.orig
cp $ROOT/toolchains/${TOOCHAINFILE} $ROOT/toolchains/${TOOCHAINFILE}.orig
eval "sed -e \"s/\(.*CMAKE_C_COMPILER \).*)/\1${TOOLCHAIN}-gcc)/\" -i $ROOT/toolchains/${TOOCHAINFILE}"

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

[ "${machine}" != "" ] && machine="_${machine}"
[ -f $ROOT/config.h.orig ] && mv $ROOT/config.h.orig $ROOT/config.h
[ -f $ROOT/toolchains/${TOOCHAINFILE}.orig ] && mv $ROOT/toolchains/${TOOCHAINFILE}.orig $ROOT/toolchains/${TOOCHAINFILE}
[ -d ${builddir}/image${machine}/usr/bin ] || mkdir -p ${builddir}/image${machine}/usr/bin
cp $ROOT/build/.tmp/oscam ${builddir}/image${machine}/usr/bin/
if [ -x $TOOLCHAIN_STAGE/upx ]; then
	cp $TOOLCHAIN_STAGE/upx $ROOT/build/.tmp/
	$ROOT/build/.tmp/upx ${builddir}/image${machine}/usr/bin/oscam >/dev/null
fi

##################################################################

svnver=`$ROOT/config.sh --oscam-revision`
[ -f $ROOT/config.sh.orig ] && mv $ROOT/config.sh.orig $ROOT/config.sh

cd ${builddir}/image${machine}
if [ $# -ge 1 -a "$1" = "-debug" ]; then
	compile_time=$(date +%Y%m%d%H%M)D
else
	compile_time=$(date +%Y%m%d)
fi
[ "$libc" = "" ] || libc=-$libc
tar czf $(dirname $builddir)/oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.tar.gz *

rm -rf $ROOT/build/.tmp/*
cd $curdir
