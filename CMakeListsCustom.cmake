
# set(CMAKE_C_STANDARD 99)
# set(CMAKE_CXX_STANDARD 11)

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-sign-compare -Wno-unused-variable -Wno-unused-function")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-sign-compare -Wno-unused-variable -Wno-unused-function")

find_package(PkgConfig REQUIRED)
pkg_check_modules(WIRESHARK REQUIRED IMPORTED_TARGET wireshark)
include_directories(${WIRESHARK_INCLUDE_DIRS})

include_directories(include)
file(GLOB_RECURSE SRC_FILES src/*.cpp)

# add_library(dlms-static STATIC ${SRC_FILES})
# target_link_libraries(dlms-static PkgConfig::WIRESHARK)
# target_compile_options(dlms-static PRIVATE -fPIC)

execute_process(
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/packet-dlms.cpp ${CMAKE_BINARY_DIR}/packet-dlms.c
)

link_directories(${CMAKE_BINARY_DIR})
add_library(dlms SHARED ${CMAKE_BINARY_DIR}/packet-dlms.c)
target_link_libraries(dlms dlms-static)

add_custom_command(
	TARGET dlms PRE_BUILD
	COMMAND echo "Executing pre-build command"
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/packet-dlms.cpp ${CMAKE_BINARY_DIR}/packet-dlms.c
	# COMMAND ar qc build/libdlms-static.a $(find build -type f -name '*.o' | tr '\n' ' ')
	COMMAND ${CMAKE_SOURCE_DIR}/build.sh 2>&1
	COMMAND echo "Done"
)

execute_process(
	COMMAND wireshark --version
	OUTPUT_VARIABLE WIRESHARK_VERSION_OUTPUT
	OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(REGEX MATCH "Wireshark [0-9]+\\.[0-9]+" WIRESHARK_VERSION_MATCH ${WIRESHARK_VERSION_OUTPUT})
string(REGEX REPLACE "Wireshark " "" WIRESHARK_VERSION ${WIRESHARK_VERSION_MATCH})
message(STATUS "Wireshark version: ${WIRESHARK_VERSION}")
install(TARGETS dlms DESTINATION /usr/lib/x86_64-linux-gnu/wireshark/plugins/${WIRESHARK_VERSION}/epan)
