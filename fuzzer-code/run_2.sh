#!/bin/sh
echo $1
echo $2 $1
cwd=$PWD
cd ../libdft64/tools
$PIN_HOME/pin -t libdft-dta.so -filename $2 -x $3 -- $1
cd $cwd
cp ../libdft64/tools/cmp.out .
cp ../libdft64/tools/lea.out .
