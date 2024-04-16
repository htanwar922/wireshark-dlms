#!/bin/sh

g++ -Wall -Wno-sign-compare -Wno-unused-variable -Wno-unused-function \
	`pkg-config --cflags-only-I wireshark` \
	-Iinclude \
	-shared \
	-fPIC \
	-o dlms.o \
	-c dlms.cpp \
&& \
ar rs libdlms.a dlms.o \
&& echo "libdlms.a created" \
&& rm dlms.o \
&& \
gcc -Wall -Wno-sign-compare \
	`pkg-config --cflags-only-I wireshark` \
	-Iinclude \
	-shared \
	-o dlms.so \
	proto.c libdlms.a \
&& echo "dlms.so created" \
&& rm libdlms.a \
&& sudo cp dlms.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/3.2/epan \
&& echo "dlms.so copied to wireshark plugins" \
&& rm dlms.so
