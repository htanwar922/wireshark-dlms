
include(WiresharkPlugin)
include(FindGCRYPT)

# Plugin name and version info (major minor micro extra)
set_module_info(dlms 0 9 0 0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB_RECURSE DISSECTOR_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/*.cpp")
set(DISSECTOR_SRC
	packet-dlms.cpp
	${DISSECTOR_SOURCES}
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_wireshark_plugin_library(dlms epan)

message(STATUS "GCRYPT_INCLUDE_DIR: ${GCRYPT_INCLUDE_DIR}")
message(STATUS "GCRYPT_LIBRARY: ${GCRYPT_LIBRARY}")

target_link_libraries(dlms epan wsutil ${GCRYPT_LIBRARY})

install_plugin(dlms epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "include/*.h")
CHECKAPI(
	NAME
	  dlms
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)
