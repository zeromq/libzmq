# CMake build script for ZeroMQ on Windows

cmake_minimum_required (VERSION 2.8)
project (ZeroMQ)

include (${CMAKE_SOURCE_DIR}/cmake/Modules/TestZMQVersion.cmake)

option (WITH_DOC "Build Reference Guide documentation (requires DocBook)" OFF)
option (WITH_OPENPGM "Build with support for OpenPGM" OFF)

# WARNING: Windows Python will override Cygwin yet not work with Asciidoc.
#find_package (PythonInterp REQUIRED)
# Workaround, manually set Python location
set(PYTHON_EXECUTABLE c:/cygwin/bin/python2.6.exe CACHE FILEPATH "Python interpreter executable")
# TODO: Replace with FindAsciidoc.cmake
set(ASCIIDOC_EXECUTABLE c:/cygwin/bin/asciidoc CACHE FILEPATH "AsciiDoc executable")

if (WITH_OPENPGM)
#	set(OPENPGM_ROOT "" CACHE PATH "Location of OpenPGM")
	set(OPENPGM_VERSION_MAJOR 5)
	set(OPENPGM_VERSION_MINOR 2)
	set(OPENPGM_VERSION_MICRO 121)
	if (CMAKE_CL_64)
		find_path(OPENPGM_ROOT include/pgm/pgm.h
			PATHS
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
			NO_DEFAULT_PATH
			)
	else (CMAKE_CL_64)
		find_path(OPENPGM_ROOT include/pgm/pgm.h
			PATHS
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
			NO_DEFAULT_PATH
			)
	endif (CMAKE_CL_64)
	message(STATUS "OpenPGM detected - ${OPENPGM_ROOT}")
	set(OPENPGM_INCLUDE_DIRS ${OPENPGM_ROOT}/include)
	set(OPENPGM_LIBRARY_DIRS ${OPENPGM_ROOT}/lib)
	set(OPENPGM_LIBRARIES
		optimized libpgm${_zmq_COMPILER}-mt-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib
		debug libpgm${_zmq_COMPILER}-mt-gd-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib)
endif (WITH_OPENPGM)

mark_as_advanced(PYTHON_EXECUTABLE ASCIIDOC_EXECUTABLE)

#-----------------------------------------------------------------------------
# force off-tree build

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   del CMakeCache.txt
   mkdir cmake-make
   cd cmake-make
   cmake ..
")
endif(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})

#-----------------------------------------------------------------------------
# default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif(NOT CMAKE_BUILD_TYPE)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_BINARY_DIR}/lib)

#-----------------------------------------------------------------------------
# platform specifics

add_definitions(
        -DWIN32
	-DDLL_EXPORT
# NB: May require tweaking for highly connected applications.
	-DFD_SETSIZE=1024
	-D_CRT_SECURE_NO_WARNINGS
)

# Parallel make.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

# Optimization flags.
# http://msdn.microsoft.com/en-us/magazine/cc301698.aspx
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE "${CMAKE_MODULE_LINKER_FLAGS_RELEASE} /LTCG")

#-----------------------------------------------------------------------------
# source files

set(cxx-sources
	address.cpp
	clock.cpp
	ctx.cpp
	dealer.cpp
	decoder.cpp
	devpoll.cpp
	dist.cpp
	encoder.cpp
	epoll.cpp
	err.cpp
	fq.cpp
	io_object.cpp
	io_thread.cpp
	ip.cpp
	ipc_address.cpp
	ipc_connecter.cpp
	ipc_listener.cpp
	kqueue.cpp
	lb.cpp
	mailbox.cpp
	msg.cpp
	mtrie.cpp
	object.cpp
	options.cpp
	own.cpp
	pair.cpp
	pgm_receiver.cpp
	pgm_sender.cpp
	pgm_socket.cpp
	pipe.cpp
	poll.cpp
	poller_base.cpp
	precompiled.cpp
	proxy.cpp
	pub.cpp
	pull.cpp
	push.cpp
	random.cpp
	reaper.cpp
	rep.cpp
	req.cpp
	router.cpp
	select.cpp
	session_base.cpp
	signaler.cpp
	socket_base.cpp
	stream_engine.cpp
	sub.cpp
	tcp.cpp
	tcp_address.cpp
	tcp_connecter.cpp
	tcp_listener.cpp
	thread.cpp
	trie.cpp
	v1_decoder.cpp
	v1_encoder.cpp
	xpub.cpp
	xsub.cpp
	zmq.cpp
	zmq_utils.cpp
)

set(rc-sources
	version.rc
)

include_directories(
        include
	${CMAKE_BINARY_DIR}
)
set(headers
	include/zmq.h
	include/zmq_utils.h
)
set(readme-docs
	AUTHORS
	COPYING
	COPYING.LESSER
	MAINTAINERS
	NEWS
	README
)

#-----------------------------------------------------------------------------
# optional modules

if(WITH_OPENPGM)
	add_definitions(
		-DZMQ_HAVE_OPENPGM
	)
	include_directories(
		${OPENPGM_INCLUDE_DIRS}
	)
	link_directories(
		${OPENPGM_LIBRARY_DIRS}
	)
	set(OPTIONAL_LIBRARIES ${OPENPGM_LIBRARIES})
endif(WITH_OPENPGM)

#-----------------------------------------------------------------------------
# source generators

foreach (source ${cxx-sources})
	list(APPEND sources ${CMAKE_SOURCE_DIR}/src/${source})
endforeach()

foreach (source ${rc-sources})
	list(APPEND sources ${CMAKE_BINARY_DIR}/${source})
	configure_file(${CMAKE_SOURCE_DIR}/src/${source}.in ${CMAKE_BINARY_DIR}/${source})
endforeach()

add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/platform.hpp
	COMMAND ${CMAKE_COMMAND}
	ARGS	-E
		copy
		${CMAKE_SOURCE_DIR}/builds/msvc/platform.hpp
		${CMAKE_BINARY_DIR}/platform.hpp
	DEPENDS ${CMAKE_SOURCE_DIR}/builds/msvc/platform.hpp
)
list(APPEND sources ${CMAKE_BINARY_DIR}/platform.hpp)

if (CMAKE_CL_64)
	set (nsis-template ${CMAKE_SOURCE_DIR}/cmake/NSIS.template64.in)
else (CMAKE_CL_64)
	set (nsis-template ${CMAKE_SOURCE_DIR}/cmake/NSIS.template32.in)
endif (CMAKE_CL_64)
add_custom_command(
	OUTPUT ${CMAKE_BINARY_DIR}/NSIS.template.in
	COMMAND ${CMAKE_COMMAND}
	ARGS    -E
		copy
		${nsis-template}
		${CMAKE_BINARY_DIR}/NSIS.template.in
	DEPENDS ${nsis-template}
)

file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/doc)
file(GLOB docs RELATIVE ${CMAKE_BINARY_DIR}/ "${CMAKE_SOURCE_DIR}/doc/*.txt")
set (html-docs)
foreach (txt ${docs})
	string (REGEX REPLACE ".*/(.*)\\.txt" "\\1.html" html ${txt})
	set (src ${txt})
	set (dst doc/${html})
	add_custom_command(
		OUTPUT  ${dst}
		COMMAND ${PYTHON_EXECUTABLE}
		ARGS    -x
			${ASCIIDOC_EXECUTABLE}
			-d manpage
			-b xhtml11
			-f ${CMAKE_SOURCE_DIR}/doc/asciidoc.conf
			-azmq_version=${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}
			-o ${dst}
			${src}
		DEPENDS ${CMAKE_BINARY_DIR}/${src}
		WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
		COMMENT "Generating ${html}"
	)
	if (WITH_DOC)
		list(APPEND html-docs ${CMAKE_BINARY_DIR}/${dst})
	endif (WITH_DOC)
endforeach (txt ${docs})

#-----------------------------------------------------------------------------
# output

add_library(libzmq SHARED ${sources} ${html-docs} ${CMAKE_BINARY_DIR}/NSIS.template.in)
target_link_libraries(libzmq ws2_32.lib rpcrt4.lib ${OPTIONAL_LIBRARIES})
set_target_properties(libzmq PROPERTIES
	RELEASE_POSTFIX "${_zmq_COMPILER}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
	DEBUG_POSTFIX "${_zmq_COMPILER}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}")

#-----------------------------------------------------------------------------
# installer

install (TARGETS libzmq ARCHIVE DESTINATION lib COMPONENT SDK)
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	install (TARGETS libzmq RUNTIME DESTINATION bin COMPONENT SDK)
	install (FILES ${CMAKE_BINARY_DIR}/lib/libzmq${_zmq_COMPILER}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}.pdb DESTINATION lib COMPONENT SDK)
else (CMAKE_BUILD_TYPE STREQUAL "Debug")
	install (TARGETS libzmq RUNTIME DESTINATION bin COMPONENT Runtime)
endif (CMAKE_BUILD_TYPE STREQUAL "Debug")
install (FILES ${headers} DESTINATION include COMPONENT SDK)

set (perf-tools
	local_lat
	remote_lat
	local_thr
	remote_thr
	inproc_lat
	inproc_thr
)
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
	foreach (perf-tool ${perf-tools})
		add_executable (${perf-tool} perf/${perf-tool}.cpp)
		target_link_libraries (${perf-tool} libzmq)
		install (TARGETS ${perf-tool} RUNTIME DESTINATION bin COMPONENT PerfTools)
	endforeach (perf-tool ${perf-tools})
endif (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")

file(GLOB headers "${CMAKE_SOURCE_DIR}/src/*.hpp")
install (FILES ${sources} ${headers} DESTINATION src COMPONENT SourceCode)

foreach (readme ${readme-docs})
	configure_file (${CMAKE_SOURCE_DIR}/${readme} ${CMAKE_BINARY_DIR}/${readme}.txt)
	install (FILES ${CMAKE_BINARY_DIR}/${readme}.txt DESTINATION .)
endforeach (readme ${readme-docs})
if (WITH_DOC)
	install (FILES ${html-docs} DESTINATION doc COMPONENT RefGuide)
endif (WITH_DOC)

include (InstallRequiredSystemLibraries)

if (CMAKE_CL_64)
	set (CPACK_NSIS_DISPLAY_NAME "ZeroMQ ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH} (x64)")
        set (CPACK_PACKAGE_FILE_NAME "ZeroMQ-${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}-x64")
	set (CPACK_INSTALL_CMAKE_PROJECTS
		"${CMAKE_SOURCE_DIR}/build/x64/v110;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x64/v110;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/build/x64/v100;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x64/v100;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/build/x64/v90;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x64/v90;ZeroMQ;ALL;/"
	)
else (CMAKE_CL_64)
	set (CPACK_NSIS_DISPLAY_NAME "ZeroMQ ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}")
        set (CPACK_PACKAGE_FILE_NAME "ZeroMQ-${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}-x86")
	set (CPACK_INSTALL_CMAKE_PROJECTS
		"${CMAKE_SOURCE_DIR}/build/x86/v110;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x86/v110;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/build/x86/v100;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x86/v100;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/build/x86/v90;ZeroMQ;ALL;/"
		"${CMAKE_SOURCE_DIR}/debug/x86/v90;ZeroMQ;ALL;/"
	)
endif (CMAKE_CL_64)
set (CMAKE_MODULE_PATH "${CMAKE_BINARY_DIR}")
set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "ZeroMQ lightweight messaging kernel")
set (CPACK_PACKAGE_VENDOR "Miru")
set (CPACK_NSIS_CONTACT "Steven McCoy <Steven.McCoy@miru.hk>")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/COPYING.txt")
# There is a bug in NSI that does not handle full unix paths properly. Make
# sure there is at least one set of four (4) backlasshes.
set (CPACK_NSIS_MUI_ICON "${CMAKE_SOURCE_DIR}\\\\installer.ico")
set (CPACK_NSIS_MUI_UNIICON "${CMAKE_SOURCE_DIR}\\\\installer.ico")
set (CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}\\\\branding.bmp")
set (CPACK_NSIS_COMPRESSOR "/SOLID lzma")
set (CPACK_PACKAGE_VERSION_MAJOR "${ZMQ_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${ZMQ_VERSION_MINOR}")
set (CPACK_PACKAGE_VERSION_PATCH "${ZMQ_VERSION_PATCH}")

include (CPack)

cpack_add_component_group (Development
	DISPLAY_NAME "ZeroMQ software development kit"
	EXPANDED
)
cpack_add_component (PerfTools
	DISPLAY_NAME "ZeroMQ performance tools"
	INSTALL_TYPES FullInstall DevInstall
)
cpack_add_component (SourceCode
	DISPLAY_NAME "ZeroMQ source code"
	DISABLED
	INSTALL_TYPES FullInstall
)
cpack_add_component (SDK
	DISPLAY_NAME "ZeroMQ headers and libraries"
	INSTALL_TYPES FullInstall DevInstall
	GROUP Development
)
if (WITH_DOC)
	cpack_add_component (RefGuide
		DISPLAY_NAME "ZeroMQ reference guide"
		INSTALL_TYPES FullInstall DevInstall
		GROUP Development
	)
endif (WITH_DOC)
cpack_add_component (Runtime
	DISPLAY_NAME "ZeroMQ runtime files"
	REQUIRED
	INSTALL_TYPES FullInstall DevInstall MinInstall
)
cpack_add_install_type (FullInstall
	DISPLAY_NAME "Full install, including source code"
)
cpack_add_install_type (DevInstall
	DISPLAY_NAME "Developer install, headers and libraries"
)
cpack_add_install_type (MinInstall
	DISPLAY_NAME "Minimal install, runtime only"
)

# end of file
