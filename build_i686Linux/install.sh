#!/bin/sh
plat=i686-pc-linux
plat_dir=build_i686Linux
rm -f oscam oscam-$plat-svn*.tar.gz oscam-$plat-svn*.deb

make clean
cmake  -DCS_CONFDIR=/var/etc -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make

[ -d image/usr/bin ] || mkdir -p image/usr/bin
cp oscam image/usr/bin/

curdir=`pwd`
builddir=`dirname $0`
[ "$builddir" = "." ] && svnroot=".."
[ "$builddir" = "." ] || svnroot=`dirname $builddir`
csver=`grep "CS_VERSION" $svnroot/globals.h | sed -e "s/[^\"]*//" -e "s/\"//g" | cut -f1 -d-`
svnver=`svnversion  -c ${svnroot} | cut -f 2 -d: | sed -e "s/[^[:digit:]]//g"`
cd ${svnroot}/${plat_dir}/image
sed -i "s/Version:.*/Version: ${csver}-svn${svnver}/" DEBIAN/control
tar czf ../oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.tar.gz var usr
cd ../ 
dpkg -b image oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.deb
rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo image/usr/bin/oscam
cd $curdir
