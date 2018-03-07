##############################################################
[ "$curdir" = "" ] && curdir=`pwd`
[ "$builddir" = "" ] && builddir=`cd $(dirname $0);pwd`

ERROR=0

[ -f $curdir/oscam.c -a -f $curdir/module-dvbapi.c ] && OSCAM_SRC=$curdir

if [ "${OSCAM_SRC}" != "" -a -f ${OSCAM_SRC}/oscam.c ]; then
	ROOT=$(cd ${OSCAM_SRC};pwd)
elif [ -f $(dirname $(dirname $builddir))/oscam.c ]; then
	ROOT=$(dirname $(dirname $builddir))
else
	echo "Not found oscam source directory! Please set OSCAM_SRC environment value..."
	cd $curdir
	ERROR=1
fi

###### guesst target execute binary #######

if [ "${OSCAM_TARGET}" = "" ]; then
	if echo $TOOLCHAIN | grep -qi cygwin; then 
		OSCAM_TARGET=/oscam.exe
	elif echo $TOOCHAINFILE | grep -qi azbox; then
		OSCAM_TARGET=/PLUGINS/OpenXCAS/oscamCAS/oscam
	elif echo $TOOCHAINFILE | grep -qi dm500; then
		OSCAM_TARGET=/var/bin/oscam
	elif echo $TOOCHAINFILE | grep -qi Android; then
		OSCAM_TARGET=/data/data/oscam/oscam
	else
		OSCAM_TARGET=/usr/bin/oscam
	fi
fi
OSCAM_TARGET=$(echo ${OSCAM_TARGET}| sed -e "s/^\///")

#---- clean building dir ---------
rm -f $builddir/*.ipk
rm -f ${builddir}/image${machine}/${OSCAM_TARGET}
rm -f ${builddir}/image${machine}/$(dirname ${OSCAM_TARGET})/*.upx
rm -rf $ROOT/build/.tmp/*

[ $ERROR -eq 1 ] && exit

######### parse option #######################
buildtype="default"
for op in "$@"; do
   [ "$op" = "-debug" -o "$op" = "debug" ] && debug=1
   [ "$op" = "-inline" -o "$op" = "inline" ] && buildtype="inline"
done

# fix config.sh for subverison changed to git
if [ -f $ROOT/config.sh ]; then
	cp $ROOT/config.sh $ROOT/config.sh.orig
	sed -e "s/^[[:space:]]*\((svnversion .*\)/\
		revision=\`\1\`\n\
\n\
		if [ \"\$revision\" = \"\" -o \"\$revision\" = \"0\" ]; then\n\
			svnrevision=\$(git log 2>\/dev\/null | grep git-svn-id | sed -n 1p | cut -d\@ -f2 | cut -d\' \' -f1)\n\
			gitrevision=\$(git log 2>\/dev\/null | sed -n 1p|cut -d\' \' -f2 | cut -c1-5 )\n\
			if [ \"\$svnrevision\" = \"\" -o \"\$gitrevision\" = \"0\" ]; then\n\
				[ -f history.txt ] \&\& gitrevision=\$(cat history.txt | sed -n 1p | cut -d\' \' -f1)\n\
				[ -f .svnrevision ] \&\& svnrevision=\$(cat .svnrevision)\n\
			else\n\
				git log --pretty=oneline -n 100 | sed -e \"s\/^\\\([[:print:]]\\\{5,5\\\}\\\)[^[:space:]]\*\\\( .\*\\\)\/\\\1\\\2\/\" > history.txt\n\
				echo \$svnrevision > .svnrevision\n\
			fi\n\
			[ \"\$svnrevision\" = \"0\" ] \|\| revision=\$svnrevision\n\
			[ \"\$gitrevision\" = \"0\" ] \|\| revision=\${revision}_\${gitrevision}\n\
		fi\n\
		echo \$revision\n\
/" -i $ROOT/config.sh

fi

[ -d $ROOT/build/.tmp ] || mkdir -p $ROOT/build/.tmp
rm -rf $ROOT/build/.tmp/*

[ "${TOOLCHAIN_STAGE}" = "" ] && TOOLCHAIN_STAGE=$(dirname $ROOT)/toolchains
if [ ! -f ${TOOLCHAIN_STAGE}/${TOOLCHAIN_ROOT}/bin/$TOOLCHAIN-gcc ]; then
	echo "Not found $TOOLCHAIN-gcc..."
	exit
fi
##################################################################
cd $ROOT/build/.tmp
[ -f $ROOT/config.h ] && cp $ROOT/config.h $ROOT/config.h.orig
cp $ROOT/toolchains/${TOOCHAINFILE} $ROOT/toolchains/${TOOCHAINFILE}.orig
[ -f $ROOT/history.txt ] && cp $ROOT/history.txt $ROOT/history.txt.orig
eval "sed -e \"s/\(.*CMAKE_C_COMPILER \).*)/\1${TOOLCHAIN}-gcc)/\" -i $ROOT/toolchains/${TOOCHAINFILE}"

