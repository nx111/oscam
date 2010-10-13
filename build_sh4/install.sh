#!/bin/sh
export OLDPATH=$PATH
export PATH=../../toolchains/sh4/bin:$OLDPATH     # 指定编译源码时要用的sh4环境下的GCC和C++编译器路径
make clean
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchains/toolchain-sh4-qboxhd.cmake -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make
export PATH=$OLDPATH
