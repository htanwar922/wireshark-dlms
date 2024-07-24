
find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS  "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
file(GLOB_RECURSE DISSECTOR_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/*.cpp")
set(DISSECTOR_SRC
	packet-dlms.cpp
	${DISSECTOR_SOURCES}
)

add_library(dlms MODULE ${DISSECTOR_SRC})
set_target_properties(dlms PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(dlms epan)

# This is the normal installation target to CMAKE_INSTALL_PREFIX. It is relocatable
# using DESTDIR or cmake --install. By default CMAKE_INSTALL_PREFIX should be configured
# correctly for Wireshark's system installation prefix.
install(TARGETS dlms
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# This custom target installs the plugin to the plugin dir in WiresharkConfig.cmake.
# It does not use CMAKE_INSTALL_PREFIX.
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:dlms> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
	COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

string(TOLOWER "${PROJECT_NAME}-${PROJECT_VERSION}" _pkgname)

add_custom_target(package_prep
	COMMAND ${CMAKE_COMMAND} -E make_directory  ${CMAKE_BINARY_DIR}/${_pkgname}
	COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/README $<TARGET_FILE:dlms> ${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
	COMMAND ${CMAKE_COMMAND} -E tar czf ${CMAKE_BINARY_DIR}/${_pkgname}.tar.gz --format=gnutar -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
	COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/${_pkgname}.zip --format=zip -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package_zip package_prep)
