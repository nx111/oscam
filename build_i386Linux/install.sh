#!/bin/sh
make clean
cmake  -DCS_CONFDIR=/var/etc -DWEBIF=1 ..    #用cmake命令对源码进行交叉编译
make

