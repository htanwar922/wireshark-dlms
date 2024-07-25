#!/bin/sh

WIRESHARK_VERSION=`wireshark --version | grep -E "Wireshark [0-9].[0-9].[0-9]" | awk '{print $2}'`

if [ ! -d "build" ]; then
	mkdir build
fi
SRC_FILES="$(find src -type f -name '*.cpp' | tr '\n' ' ' )"

for file in $SRC_FILES; do
	echo "Compiling $file"
	if [ ! -d "build/$(dirname $file)" ]; then
		mkdir "build/$(dirname $file)"
	fi
	g++ -Wall -Wno-sign-compare -Wno-unused-variable -Wno-unused-function \
		`pkg-config --cflags-only-I wireshark` \
		-Iinclude \
		-shared \
		-fPIC \
		-o build/${file%.cpp}.o \
		-c $file 2>&1 #/dev/null
	if [ $? -ne 0 ]; then
		echo "Error compiling $file"
		exit 1
	fi
done

cp packet-dlms.cpp build/packet-dlms.c

ar rs build/libdlms.a $(find build -type f -name "*.o" | tr '\n' ' ') \
&& gcc -Wall -Wno-sign-compare \
	`pkg-config --cflags-only-I wireshark` \
	-Iinclude \
	-shared \
	-o build/libdlms.so \
	build/packet-dlms.c build/libdlms.a \
&& sudo cp build/libdlms.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/${WIRESHARK_VERSION%.*}/epan
[ $? -ne 0 ] && echo "Error linking libdlms.so" && exit 1
