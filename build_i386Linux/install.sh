#!/bin/sh
plat=i386Linux
rm -f oscam oscam-$plat-svn*.tar.gz

make clean
cmake  -DCS_CONFDIR=/var/etc -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make

[ -d image/usr/bin ] || mkdir -p image/usr/bin
cp oscam image/usr/bin/

curdir=`pwd`
builddir=`dirname $0`
[ "$builddir" = "." ] && svnroot=".."
[ "$builddir" = "." ] || svnroot=`dirname $builddir`
cd $svnroot/
svnver=`svn info | sed -n "5p"| sed -e "s/ //g" | cut -f2 -d:`
cd build_$plat/image
tar czf ../oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.tar.gz *
cd ../ 
rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo image/usr/bin/oscam
cd $curdir
