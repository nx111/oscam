#!/bin/sh

plat=i686-pc-cygwin
plat_dir=build_cygwin

rm -f oscam oscam-nx111  
export OLDPATH=$PATH
export PATH=../../toolchains/i686-pc-cygwin/bin:$OLDPATH     # 指定编译源码时要用的mipsel环境下的GCC和C++编译器路径
make clean
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/toolchain-i386-cygwin.cmake -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make
export PATH=$OLDPATH


rm -rf CMake* *.a Makefile cscrypt csctapi *.cmake algo 
