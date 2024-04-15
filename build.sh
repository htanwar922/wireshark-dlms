#!/bin/sh
# exec gcc -O2 -Wall `pkg-config --cflags-only-I wireshark` -Iinclude -shared -o dlms.so dlms.c -s

exec g++ -O2 -Wall `pkg-config --cflags-only-I wireshark` -Iinclude -shared -o dlms.so dlms.c -s
