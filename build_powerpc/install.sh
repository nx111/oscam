#!/bin/sh

plat=powerpc
rm -f oscam oscam-nx111  oscam-$plat-svn*.tar.gz
export OLDPATH=$PATH
export PATH=../../toolchains/powerpc-tuxbox-linux-gnu/bin:$OLDPATH     # 指定编译源码时要用的PowerPC环境下的GCC和C++编译器路径
make clean
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/toolchain-powerpc-tuxbox.cmake -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make
export PATH=$OLDPATH

[ -d image/var/bin ] || mkdir -p image/var/bin
cp oscam image/var/bin/

curdir=`pwd`
builddir=`dirname $0`
[ "$builddir" = "." ] && svnroot=".."
[ "$builddir" = "." ] || svnroot=`dirname $builddir`
cd $svnroot/
svnver=`svn info | sed -n "5p"| sed -e "s/ //g" | cut -f2 -d:`
cd build_$plat/image
tar czf ../oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.tar.gz *
cd ../ 
rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo
cd $curdir
