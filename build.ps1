# & 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsx86_amd64.bat'

set WS_SRC_DIR ${env:WIRESHARK_BASE_DIR}\\wireshark
set WS_BUILD_DIR ${env:WIRESHARK_BASE_DIR}\\wsbuild64
set WS_LIB_DIR ${env:WIRESHARK_BASE_DIR}\\wireshark-x64-libs

set WS_RUN_DIR ${WS_SRC_DIR}\\run\\RelWithDebInfo
set WS_VCPKG_DIR ${WS_LIB_DIR}\\vcpkg-export-20240524-1-x64-windows-ws\\installed\\x64-windows

$INCLUDES = "
	/I${WS_SRC_DIR}
	/I${WS_SRC_DIR}\\include
	/I${WS_BUILD_DIR}
	/I${WS_VCPKG_DIR}\\include\\glib-2.0
	/I${WS_VCPKG_DIR}\\lib\\glib-2.0\\include
	/I${pwd}
	/I${pwd}\\include
".replace("`n", " ").replace("`r", "").replace("`t", "")

$LINKS = "
	${WS_BUILD_DIR}
	${WS_LIB_DIR}
".replace("`n", " ").replace("`r", "").replace("`t", "")

cl.exe /W2 /nologo /O2 ${INCLUDES} /LD dlms.cpp
gcc -Wall -Wno-sign-compare \
	-I/usr/include/wireshark -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	-Iinclude \
	-shared \
	-o dlms.so \
	proto.c libdlms.a \
&& echo "dlms.so created" \
&& rm libdlms.a \
&& sudo cp dlms.so /usr/lib/x86_64-linux-gnu/wireshark/plugins/${WIRESHARK_VERSION%.*}/epan \
&& echo "dlms.so copied to wireshark plugins" \
&& rm dlms.so
