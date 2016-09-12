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
	if [ -f ${builddir}/image${machine}/CONTROL/control -a -x $(dirname ${builddir})/include/ipkg-build ]; then
		revision=$($ROOT/config.sh --oscam-revision)
		total_size=$(du -bsc $builddir/image$machine | sed -n 1p | cut -d$'\t' -f1)
		control_size=$(du -bsc $builddir/image$machine/CONTROL | sed -n 1p | cut -d$'\t' -f1)
		target_size=$(( total_size - control_size ))
		sed -e "s/^\([[:space:]]*Version:\).*/\1 ${revision}/" -e "s/^\([[:space:]]*Installed-Size:\).*/\1 ${target_size}/" \
		    -e "s/^\([[:space:]]*Architecture:\).*/\1 ${plat}/" -i ${builddir}/image${machine}/CONTROL/control
		$(dirname ${builddir})/include/ipkg-build -c ${builddir}/image${machine} ${builddir} > /dev/null
		ipkfile=$(find $builddir -name *.ipk |xargs basename)
		if [ "$ipkfile" != "" ] ; then
			mv $builddir/$ipkfile $(dirname $builddir)/oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.ipk
			echo
			echo "Building oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.ipk successed!"
		fi
	else
		tar czf $(dirname $builddir)/oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.tar.gz *
		echo
		echo "Building oscam-${plat}${libc}-r${svnver}${feature}-nx111-${compile_time}.tar.gz successed!"
	fi
fi
echo

rm -rf $ROOT/build/.tmp/*
cd $curdir
