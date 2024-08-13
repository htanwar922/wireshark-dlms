#!/bin/sh

WIRESHARK_VERSION=`wireshark --version | grep -E "Wireshark [0-9].[0-9].[0-9]" | awk '{print $2}'`

basedir=$(dirname $0)
bindir=$basedir/build

if [ ! -d "$bindir" ]; then
	mkdir $bindir
fi

cd $basedir
SRC_FILES="$(find src -type f -name '*.cpp' | tr '\n' ' ' )"
cd -

i=0
for file in $SRC_FILES; do
	if [ $i -eq 40 ]; then
		break
	fi
	i=$((i+1))
	echo "Compiling $file"
	# dir=$bindir/$(dirname $file); objfile=${file%.cpp}.o
	dir=$bindir/CMakeFiles/dlms-static.dir/$(dirname $file); objfile=$file.o
	if [ ! -d "$dir" ]; then
		echo "Creating directory $dir"
		mkdir -p "$dir"
	fi
	g++ -Wall -Wno-sign-compare -Wno-unused-variable -Wno-unused-function \
		`pkg-config --cflags-only-I wireshark` \
		-I$basedir/include \
		-fPIC \
		-c $basedir/$file \
		-o $dir/$(basename $objfile)
	if [ $? -ne 0 ]; then
		echo "Error compiling $file"
		exit 1
	fi
done

cp $basedir/packet-dlms.cpp $bindir/packet-dlms.c

ar rs $bindir/libdlms-static.a $(find $bindir -type f -name "*.o" | tr '\n' ' ') \
&& ranlib $bindir/libdlms-static.a \
# && \
# gcc -Wall -Wno-sign-compare \
# 	`pkg-config --cflags-only-I wireshark` \
# 	-Iinclude \
# 	-shared \
# 	-o $bindir/libdlms.so \
# 	$bindir/packet-dlms.c $bindir/libdlms-static.a \
# && \
# sudo cp $bindir/libdlms.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/${WIRESHARK_VERSION%.*}/epan
[ $? -eq 0 ] && echo "Build successful" || echo "Build failed"
