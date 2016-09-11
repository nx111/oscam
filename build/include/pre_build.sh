##############################################################
[ "$curdir" = "" ] && curdir=`pwd`
[ "$builddir" = "" ] && builddir=`cd $(dirname $0);pwd`

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

###### guesst target execute binary #######

if [ "${OSCAM_TARGET}" = "" ]; then
	if echo $TOOLCHAIN | grep -qi cygwin; then 
		OSCAM_TARGET=/oscam.exe
	elif echo $TOOCHAINFILE | grep -qi azbox; then
		OSCAM_TARGET=/PLUGINS/OpenXCAS/oscamCAS/oscam
	elif echo $TOOCHAINFILE | grep -qi dm500; then
		OSCAM_TARGET=/var/bin/oscam
	else
		OSCAM_TARGET=/usr/bin/oscam
	fi
fi
OSCAM_TARGET=$(echo ${OSCAM_TARGET}| sed -e "s/^\///")

######### parse option #######################
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
	exit
fi
##################################################################
cd $ROOT/build/.tmp
[ -f $ROOT/config.h ] && cp $ROOT/config.h $ROOT/config.h.orig
cp $ROOT/toolchains/${TOOCHAINFILE} $ROOT/toolchains/${TOOCHAINFILE}.orig
eval "sed -e \"s/\(.*CMAKE_C_COMPILER \).*)/\1${TOOLCHAIN}-gcc)/\" -i $ROOT/toolchains/${TOOCHAINFILE}"

