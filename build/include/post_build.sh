#############################################################
[ "${machine}" != "" ] && machine="_${machine}"
[ -f $ROOT/config.h.orig ] && mv $ROOT/config.h.orig $ROOT/config.h
[ -f $ROOT/toolchains/${TOOCHAINFILE}.orig ] && mv $ROOT/toolchains/${TOOCHAINFILE}.orig $ROOT/toolchains/${TOOCHAINFILE}
[ -d ${builddir}/image${machine}/$(dirname ${OSCAM_TARGET}) ] || mkdir -p ${builddir}/image${machine}/$(dirname ${OSCAM_TARGET})

if [ -f $ROOT/build/.tmp/$(basename ${OSCAM_TARGET}) ]; then
	cp $ROOT/build/.tmp/$(basename ${OSCAM_TARGET}) ${builddir}/image${machine}/$(dirname ${OSCAM_TARGET})/
	if [ -x $TOOLCHAIN_STAGE/upx ]; then
		cp $TOOLCHAIN_STAGE/upx $ROOT/build/.tmp/
		$ROOT/build/.tmp/upx ${builddir}/image${machine}/${OSCAM_TARGET} >/dev/null
	fi
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
if [ -f ${builddir}/image${machine}/${OSCAM_TARGET} ]; then
	[ "$libc" = "" ] || libc=-$libc
	tar czf $(dirname $builddir)/oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.tar.gz *
fi

rm -rf $ROOT/build/.tmp/*
cd $curdir
