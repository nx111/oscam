#!/bin/sh

plat=powerpc
plat_dir=build_powerpc
rm -f oscam oscam-nx111  oscam-$plat-svn*.tar.gz oscam-$plat-svn*.ipk
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
csver=`grep "CS_VERSION" $svnroot/globals.h | sed -e "s/[^\"]*//" -e "s/\"//g" | cut -f1 -d-`
svnver=`svnversion  -c ${svnroot} | cut -f 2 -d: | sed -e "s/[^[:digit:]]//g"`
cd ${svnroot}/${plat_dir}/image
sed -i "s/Version:.*/Version: ${csver}-svn${svnver}/" DEBIAN/control
tar czf ../oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.tar.gz var
cd ../ 
dpkg -b image oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.ipk
rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo image/var/bin/oscam
cd $curdir
