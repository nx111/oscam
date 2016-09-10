#!/bin/sh

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

find $builddir -name "build*.sh" ! -path $builddir/$(basename $0)  | while read f; do
	OSCAM_SRC=$ROOT $f $*
done

cd $curdir
