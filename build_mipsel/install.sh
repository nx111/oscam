#!/bin/sh

plat=mipsel
plat_dir=build_mipsel

rm -f oscam oscam-nx111  oscam-$plat-svn*.tar.gz oscam-$plat-svn*.ipk
export OLDPATH=$PATH
export PATH=../../toolchains/mipsel-unknown-linux-gnu/bin:$OLDPATH     # 指定编译源码时要用的mipsel环境下的GCC和C++编译器路径
make clean
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/toolchain-mips-tuxbox.cmake -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make
export PATH=$OLDPATH
cp oscam oscam-release

[ -d image/usr/bin ] || mkdir -p image/usr/bin
cp oscam image/usr/bin/

curdir=`pwd`
builddir=`dirname $0`
[ "$builddir" = "." ] && svnroot=".."
[ "$builddir" = "." ] || svnroot=`dirname $builddir`
csver=`grep "CS_VERSION" $svnroot/globals.h | sed -e "s/[^\"]*//" -e "s/\"//g" | cut -f1 -d-`
svnver=`svnversion  -c ${svnroot} | cut -f 2 -d: | sed -e "s/[^[:digit:]]//g"`
cd ${svnroot}/${plat_dir}/image
sed -i "s/oscam_version=.*/oscam_version=${csver}-svn${svnver}/" etc/init.d/softcam.oscam
sed -i "s/Version:.*/Version: ${csver}-svn${svnver}/" DEBIAN/control
tar czf ../oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.tar.gz usr etc var
cd ../ 
dpkg -b image oscam-${plat}-svn${svnver}-nx111-`date +%Y%m%d`.ipk
rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo image/usr/bin/oscam
cd $curdir
