# CMake build script for ZeroMQ

cmake_minimum_required (VERSION 2.8.12)
project (ZeroMQ)

list (INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}")

include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=gnu++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
endif()
include(CheckCCompilerFlag)
CHECK_C_COMPILER_FLAG("-std=gnu11" COMPILER_SUPPORTS_C11)
if(COMPILER_SUPPORTS_C11)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
endif()

# Will be used to add flags to pkg-config useful when apps want to statically link
set (pkg_config_libs_private "")

option (WITH_OPENPGM "Build with support for OpenPGM" OFF)
option (WITH_VMCI "Build with support for VMware VMCI socket" OFF)

if (APPLE)
    option (ZMQ_BUILD_FRAMEWORK "Build as OS X framework" OFF)
endif ()

# Select curve encryption library, defaults to tweetnacl
# To use libsodium instead, use --with-libsodium (must be installed)
# To disable curve, use --disable-curve

option (WITH_LIBSODIUM "Use libsodium instead of built-in tweetnacl" OFF)
option (ENABLE_CURVE "Enable CURVE security" ON)

if (NOT ENABLE_CURVE)
    message (STATUS "CURVE security is disabled")

elseif (WITH_LIBSODIUM)
    find_package (Sodium)
    if (SODIUM_FOUND)
        message (STATUS "Using libsodium for CURVE security")
        include_directories (${SODIUM_INCLUDE_DIRS})

        # On Solaris, libsodium depends on libssp
        if (${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
            target_link_libraries (libzmq ssp)
        endif ()
        set (ZMQ_USE_LIBSODIUM 1)
        set (ZMQ_HAVE_CURVE 1)
        set (pkg_config_libs_private "${pkg_config_libs_private} -lsodium")
    else ()
        message (FATAL_ERROR
            "libsodium is not installed. Install it, then run CMake again")
    endif ()

else ()
    message (STATUS "Using tweetnacl for CURVE security")
    list (APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/src/tweetnacl.c)
    set (ZMQ_USE_TWEETNACL 1)
    set (ZMQ_HAVE_CURVE 1)
endif ()

set(SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

if (EXISTS "${SOURCE_DIR}/.git")
    OPTION (ENABLE_DRAFTS "Build and install draft classes and methods" ON)
else ()
    OPTION (ENABLE_DRAFTS "Build and install draft classes and methods" OFF)
endif ()
IF (ENABLE_DRAFTS)
    ADD_DEFINITIONS (-DZMQ_BUILD_DRAFT_API)
    set (pkg_config_defines "-DZMQ_BUILD_DRAFT_API=1")
ELSE (ENABLE_DRAFTS)
    set (pkg_config_defines "")
ENDIF (ENABLE_DRAFTS)

option (WITH_MILITANT "Enable militant assertions" OFF)
if (WITH_MILITANT)
    add_definitions(-DZMQ_ACT_MILITANT)
endif()

set (POLLER "" CACHE STRING "Choose polling system. valid values are
                            kqueue, epoll, devpoll, pollset, poll or select [default=autodetect]")

include (CheckFunctionExists)
include (CheckTypeSize)

if (POLLER STREQUAL "")
    set (CMAKE_REQUIRED_INCLUDES sys/event.h)
    check_function_exists (kqueue HAVE_KQUEUE)
    set (CMAKE_REQUIRED_INCLUDES)
    if (HAVE_KQUEUE)
        set (POLLER "kqueue")
    endif()
endif ()

if (POLLER STREQUAL "")
    set (CMAKE_REQUIRED_INCLUDES sys/epoll.h)
    check_function_exists (epoll_create HAVE_EPOLL)
    set (CMAKE_REQUIRED_INCLUDES)
    if (HAVE_EPOLL)
        set (POLLER "epoll")
        check_function_exists (epoll_create1 HAVE_EPOLL_CLOEXEC)
        if (HAVE_EPOLL_CLOEXEC)
            set (ZMQ_USE_EPOLL_CLOEXEC 1)
        endif ()
    endif ()
endif ()

if (POLLER STREQUAL "")
    set (CMAKE_REQUIRED_INCLUDES sys/devpoll.h)
    check_type_size ("struct pollfd" DEVPOLL)
    set (CMAKE_REQUIRED_INCLUDES)
    if (HAVE_DEVPOLL)
        set (POLLER "devpoll")
    endif ()
endif ()

if (POLLER STREQUAL "")
    set (CMAKE_REQUIRED_INCLUDES sys/pollset.h)
    check_function_exists (pollset_create HAVE_POLLSET)
    set (CMAKE_REQUIRED_INCLUDES)
    if (HAVE_POLLSET)
        set (POLLER "pollset")
    endif()
endif ()

if (POLLER STREQUAL "")
    set (CMAKE_REQUIRED_INCLUDES poll.h)
    check_function_exists (poll HAVE_POLL)
    set (CMAKE_REQUIRED_INCLUDES)
    if (HAVE_POLL)
        set (POLLER "poll")
    endif ()
endif ()

if (POLLER STREQUAL "")
    if (WIN32)
        set (CMAKE_REQUIRED_INCLUDES winsock2.h)
        set (HAVE_SELECT 1)
    else ()
        set (CMAKE_REQUIRED_INCLUDES sys/select.h)
        check_function_exists (select HAVE_SELECT)
        set (CMAKE_REQUIRED_INCLUDES)
    endif ()
    if (HAVE_SELECT)
        set (POLLER "select")
    else ()
        message (FATAL_ERROR
            "Could not autodetect polling method")
    endif ()
endif ()

if (POLLER STREQUAL "kqueue"
 OR POLLER STREQUAL "epoll"
 OR POLLER STREQUAL "devpoll"
 OR POLLER STREQUAL "pollset"
 OR POLLER STREQUAL "poll"
 OR POLLER STREQUAL "select")
    message (STATUS "Detected ${POLLER} polling method")
    string (TOUPPER ${POLLER} UPPER_POLLER)
    set (ZMQ_USE_${UPPER_POLLER} 1)
else ()
    message (FATAL_ERROR "Invalid polling method")
endif ()

set (ZMQ_CMAKE_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/Modules)
list (APPEND CMAKE_MODULE_PATH ${ZMQ_CMAKE_MODULES_DIR})

include (TestZMQVersion)
include (ZMQSourceRunChecks)
include (CheckIncludeFiles)
include (CheckLibraryExists)
include (CheckCCompilerFlag)
include (CheckCXXCompilerFlag)
include (CheckCSourceCompiles)
include (CheckCSourceRuns)
include (CMakeDependentOption)
include (CheckCXXSymbolExists)

check_include_files (ifaddrs.h ZMQ_HAVE_IFADDRS)
check_include_files (windows.h ZMQ_HAVE_WINDOWS)
check_include_files (sys/uio.h ZMQ_HAVE_UIO)
check_include_files (sys/eventfd.h ZMQ_HAVE_EVENTFD)
if (ZMQ_HAVE_EVENTFD)
  zmq_check_efd_cloexec ()
endif ()

check_library_exists (ws2_32 fopen "" HAVE_WS2_32) # TODO: Why doesn't something logical like WSAStartup work?
check_library_exists (ws2 fopen "" HAVE_WS2)
check_library_exists (rpcrt4 fopen "" HAVE_RPCRT4) # UuidCreateSequential
check_library_exists (iphlpapi fopen "" HAVE_IPHLAPI) # GetAdaptersAddresses

check_cxx_symbol_exists (SO_PEERCRED sys/socket.h ZMQ_HAVE_SO_PEERCRED)
check_cxx_symbol_exists (LOCAL_PEERCRED sys/socket.h ZMQ_HAVE_LOCAL_PEERCRED)

find_library (RT_LIBRARY rt)

find_package (Threads)


if (WIN32 AND NOT CYGWIN)
  if (NOT HAVE_WS2_32 AND NOT HAVE_WS2)
    message (FATAL_ERROR "Cannot link to ws2_32 or ws2")
  endif ()

  if (NOT HAVE_RPCRT4)
    message (FATAL_ERROR "Cannot link to rpcrt4")
  endif ()

  if (NOT HAVE_IPHLAPI)
    message (FATAL_ERROR "Cannot link to iphlapi")
  endif ()
endif ()

set (CMAKE_REQUIRED_LIBRARIES rt)
check_function_exists (clock_gettime HAVE_CLOCK_GETTIME)
set (CMAKE_REQUIRED_LIBRARIES)

set (CMAKE_REQUIRED_INCLUDES unistd.h)
check_function_exists (fork HAVE_FORK)
set (CMAKE_REQUIRED_INCLUDES)

set (CMAKE_REQUIRED_INCLUDES sys/time.h)
check_function_exists (gethrtime HAVE_GETHRTIME)
set (CMAKE_REQUIRED_INCLUDES)

set (CMAKE_REQUIRED_INCLUDES stdlib.h)
check_function_exists (mkdtemp HAVE_MKDTEMP)
set (CMAKE_REQUIRED_INCLUDES)

add_definitions (-D_REENTRANT -D_THREAD_SAFE)
add_definitions (-DZMQ_CUSTOM_PLATFORM_HPP)

option (ENABLE_EVENTFD "Enable/disable eventfd" ZMQ_HAVE_EVENTFD)

macro (zmq_check_cxx_flag_prepend flag)
  check_cxx_compiler_flag ("${flag}" HAVE_FLAG_${flag})

  if (HAVE_FLAG_${flag})
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
  endif ()
endmacro ()


if (MSVC)
  zmq_check_cxx_flag_prepend ("/W3")

  if (MSVC_IDE)
    set (MSVC_TOOLSET "-${CMAKE_VS_PLATFORM_TOOLSET}")
  else ()
    set (MSVC_TOOLSET "")
  endif ()
else ()
  zmq_check_cxx_flag_prepend ("-Wall")
endif ()

if (CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  zmq_check_cxx_flag_prepend ("-Wextra")
endif ()

#   TODO: why is -Wno-long-long defined differently than in configure.ac?
zmq_check_cxx_flag_prepend ("-Wno-long-long")
zmq_check_cxx_flag_prepend ("-Wno-uninitialized")

option (LIBZMQ_PEDANTIC "" ON)
option (LIBZMQ_WERROR "" OFF)

if (LIBZMQ_PEDANTIC)
  zmq_check_cxx_flag_prepend ("-pedantic")

  if (${CMAKE_CXX_COMPILER_ID} MATCHES "Intel")
    zmq_check_cxx_flag_prepend ("-strict-ansi")
  endif ()

  if (${CMAKE_CXX_COMPILER_ID} MATCHES "SunPro")
    zmq_check_cxx_flag_prepend ("-compat=5")
  endif ()
endif ()

if (LIBZMQ_WERROR)
  zmq_check_cxx_flag_prepend ("-Werror")
  zmq_check_cxx_flag_prepend ("-errwarn=%all")
endif ()


if (CMAKE_SYSTEM_PROCESSOR MATCHES "^sparc")
  zmq_check_cxx_flag_prepend ("-mcpu=v9")
endif ()

if (${CMAKE_CXX_COMPILER_ID} MATCHES "SunPro")
  zmq_check_cxx_flag_prepend ("-features=zla")
endif ()


if (CMAKE_SYSTEM_NAME MATCHES "SunOS" OR CMAKE_SYSTEM_NAME MATCHES "NetBSD")
  message (STATUS "Checking whether atomic operations can be used")
  check_c_source_compiles (
  "
   #include <atomic.h>

    int main ()
    {
      uint32_t value;
      atomic_cas_32 (&value, 0, 0);
      return 0;
    }
    "
    HAVE_ATOMIC_H)

  if (NOT HAVE_ATOMIC_H)
    set (ZMQ_FORCE_MUTEXES 1)
  endif ()
endif ()


#-----------------------------------------------------------------------------
zmq_check_sock_cloexec ()
zmq_check_so_keepalive ()
zmq_check_tcp_keepcnt ()
zmq_check_tcp_keepidle ()
zmq_check_tcp_keepintvl ()
zmq_check_tcp_keepalive ()
zmq_check_tcp_tipc ()
zmq_check_pthread_setname ()


if (    CMAKE_SYSTEM_NAME MATCHES "Linux"
    OR CMAKE_SYSTEM_NAME MATCHES "GNU/kFreeBSD"
    OR CMAKE_SYSTEM_NAME MATCHES "GNU/Hurd"
    OR CYGWIN)
  add_definitions (-D_GNU_SOURCE)
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  add_definitions (-D__BSD_VISIBLE)
elseif (CMAKE_SYSTEM_NAME MATCHES "NetBSD")
  add_definitions (-D_NETBSD_SOURCE)
elseif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  add_definitions (-D_OPENBSD_SOURCE)
elseif (CMAKE_SYSTEM_NAME MATCHES "SunOS")
  add_definitions (-D_PTHREADS)
elseif (CMAKE_SYSTEM_NAME MATCHES "HP-UX")
  add_definitions (-D_POSIX_C_SOURCE=200112L)
  zmq_check_cxx_flag_prepend (-Ae)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
  add_definitions (-D_DARWIN_C_SOURCE)
endif ()

set (CMAKE_PYTHON_VERSION 2.7 2.6 2.5 2.4)
find_package (PythonInterp)
find_package (AsciiDoc)

cmake_dependent_option (WITH_DOC "Build Reference Guide documentation (requires DocBook)" ON
                       "PYTHONINTERP_FOUND;ASCIIDOC_FOUND" OFF)

if (MSVC)
  if (WITH_OPENPGM)
    #   set (OPENPGM_ROOT "" CACHE PATH "Location of OpenPGM")
    set (OPENPGM_VERSION_MAJOR 5)
    set (OPENPGM_VERSION_MINOR 2)
    set (OPENPGM_VERSION_MICRO 122)
    if (CMAKE_CL_64)
      find_path (OPENPGM_ROOT include/pgm/pgm.h
                PATHS
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
                NO_DEFAULT_PATH
               )
      message (STATUS "OpenPGM x64 detected - ${OPENPGM_ROOT}")
    else ()
      find_path (OPENPGM_ROOT include/pgm/pgm.h
                PATHS
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
                "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
                NO_DEFAULT_PATH
               )
      message (STATUS "OpenPGM x86 detected - ${OPENPGM_ROOT}")
    endif (CMAKE_CL_64)
    set (OPENPGM_INCLUDE_DIRS ${OPENPGM_ROOT}/include)
    set (OPENPGM_LIBRARY_DIRS ${OPENPGM_ROOT}/lib)
    set (OPENPGM_LIBRARIES
      optimized libpgm${MSVC_TOOLSET}-mt-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib
      debug libpgm${MSVC_TOOLSET}-mt-gd-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib)
  endif ()
else ()
  if (WITH_OPENPGM)
    #  message (FATAL_ERROR "WITH_OPENPGM not implemented")
    
    if (NOT OPENPGM_PKGCONFIG_NAME)
      SET (OPENPGM_PKGCONFIG_NAME "openpgm-5.2")
    endif(NOT OPENPGM_PKGCONFIG_NAME)
    
    SET (OPENPGM_PKGCONFIG_NAME ${OPENPGM_PKGCONFIG_NAME} CACHE STRING 
      "Name pkg-config shall use to find openpgm libraries and include paths"
      FORCE )
    
    find_package(PkgConfig)
    pkg_check_modules (OPENPGM  ${OPENPGM_PKGCONFIG_NAME})

    if (OPENPGM_FOUND)
        message (STATUS ${OPENPGM_PKGCONFIG_NAME}" found")
    else ()
        message (FATAL_ERROR
            ${OPENPGM_PKGCONFIG_NAME}"  not found. openpgm is searchd via `pkg-config ${OPENPGM_PKGCONFIG_NAME}`. Consider providing a valid OPENPGM_PKGCONFIG_NAME")
    endif ()

    # DSO symbol visibility for openpgm
    if (HAVE_FLAG_VISIBILITY_HIDDEN)

    elseif (HAVE_FLAG_LDSCOPE_HIDDEN)
    
    endif ()
  endif ()
endif ()


#-----------------------------------------------------------------------------
# force off-tree build

if (${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message (FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir cmake-make
   cd cmake-make
   cmake ..
")
endif ()

#-----------------------------------------------------------------------------
# default to Release build

if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  # CMAKE_BUILD_TYPE is not used for multi-configuration generators like Visual Studio/XCode
  # which instead use CMAKE_CONFIGURATION_TYPES
  set (CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif ()

set (EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set (LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)

#-----------------------------------------------------------------------------
# platform specifics

if (WIN32)
    #   Socket limit is 16K (can be raised arbitrarily)
    add_definitions (-DFD_SETSIZE=16384)
    add_definitions (-D_CRT_SECURE_NO_WARNINGS)
    add_definitions (-D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif ()

if (MSVC)
  # Parallel make.
  set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")

  # Optimization flags.
  # http://msdn.microsoft.com/en-us/magazine/cc301698.aspx
  if (NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GL")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LTCG")
    set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /LTCG")
  endif ()
endif ()


#-----------------------------------------------------------------------------
# source files

set (cxx-sources
        precompiled.cpp
        address.cpp
        client.cpp
        clock.cpp
        ctx.cpp
        curve_client.cpp
        curve_server.cpp
        dealer.cpp
        devpoll.cpp
        dgram.cpp
        dist.cpp
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
        mailbox_safe.cpp
        mechanism.cpp
        metadata.cpp
        msg.cpp
        mtrie.cpp
        object.cpp
        options.cpp
        own.cpp
        null_mechanism.cpp
        pair.cpp
        pgm_receiver.cpp
        pgm_sender.cpp
        pgm_socket.cpp
        pipe.cpp
        plain_client.cpp
        plain_server.cpp
        poll.cpp
        poller_base.cpp
        pollset.cpp
        proxy.cpp
        pub.cpp
        pull.cpp
        push.cpp
        random.cpp
        raw_encoder.cpp
        raw_decoder.cpp
        reaper.cpp
        rep.cpp
        req.cpp
        router.cpp
        select.cpp
        server.cpp
        session_base.cpp
        signaler.cpp
        socket_base.cpp
        socks.cpp
        socks_connecter.cpp
        stream.cpp
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
        v2_decoder.cpp
        v2_encoder.cpp
        xpub.cpp
        xsub.cpp
        zmq.cpp
        zmq_utils.cpp
        decoder_allocators.cpp
        socket_poller.cpp
        timers.cpp
        config.hpp
        radio.cpp
        dish.cpp
        udp_engine.cpp
        udp_address.cpp
        scatter.cpp
        gather.cpp)

set (rc-sources version.rc)

if (MINGW)
  # Generate the right type when using -m32 or -m64
  macro (set_rc_arch rc_target)
    set (CMAKE_RC_COMPILER_INIT windres)
    enable_language (RC)
    set (CMAKE_RC_COMPILE_OBJECT
        "<CMAKE_RC_COMPILER> <FLAGS> -O coff --target=${rc_target} <DEFINES> -i <SOURCE> -o <OBJECT>")
  endmacro ()

  if (NOT CMAKE_SYSTEM_PROCESSOR)
    set (CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif ()

  if (    CMAKE_SYSTEM_PROCESSOR MATCHES "i386"
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "i486"
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "i586"
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686"
     # This also happens on x86_64 systems...what a worthless variable
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86"
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"
      OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")

    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
      set_rc_arch ("pe-x86-64")
    else ()
      set_rc_arch ("pe-i386")
    endif ()
  endif ()
endif ()

include_directories (include ${CMAKE_CURRENT_BINARY_DIR})
set (public_headers include/zmq.h
                    include/zmq_utils.h)

set (readme-docs AUTHORS
                COPYING
                COPYING.LESSER
                NEWS)

#-----------------------------------------------------------------------------
# optional modules

if (WITH_OPENPGM)
  add_definitions (-DZMQ_HAVE_OPENPGM)
  include_directories (${OPENPGM_INCLUDE_DIRS})
  link_directories (${OPENPGM_LIBRARY_DIRS})
  set (OPTIONAL_LIBRARIES ${OPENPGM_LIBRARIES})
endif (WITH_OPENPGM)

if (WITH_VMCI)
    add_definitions (-DZMQ_HAVE_VMCI)
    include_directories (${VMCI_INCLUDE_DIRS})
    list (APPEND cxx-sources vmci_address.cpp vmci_connecter.cpp vmci_listener.cpp vmci.cpp)
endif (WITH_VMCI)

if (ZMQ_HAVE_TIPC)
    add_definitions (-DZMQ_HAVE_TIPC)
    list (APPEND cxx-sources tipc_address.cpp tipc_connecter.cpp tipc_listener.cpp)
endif (ZMQ_HAVE_TIPC)

#-----------------------------------------------------------------------------
# source generators

foreach (source ${cxx-sources})
  list (APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/src/${source})
endforeach ()

foreach (source ${rc-sources})
  list (APPEND sources ${CMAKE_CURRENT_BINARY_DIR}/${source})
  configure_file (${CMAKE_CURRENT_SOURCE_DIR}/src/${source}.in ${CMAKE_CURRENT_BINARY_DIR}/${source})
endforeach ()

#   Delete any src/platform.hpp left by configure
file (REMOVE ${CMAKE_CURRENT_SOURCE_DIR}/src/platform.hpp)

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/platform.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/platform.hpp)
list (APPEND sources ${CMAKE_CURRENT_BINARY_DIR}/platform.hpp)

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/src/libzmq.pc.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc @ONLY)
set (zmq-pkgconfig ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc)

if (NOT ZMQ_BUILD_FRAMEWORK)
  install (FILES ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc DESTINATION lib/pkgconfig)
endif ()

if (MSVC)
  if (CMAKE_CL_64)
    set (nsis-template ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/NSIS.template64.in)
  else ()
    set (nsis-template ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/NSIS.template32.in)
  endif ()

  add_custom_command (
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in
    COMMAND ${CMAKE_COMMAND}
    ARGS -E
    copy
    ${nsis-template}
    ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in
    DEPENDS ${nsis-template})
endif ()

file (MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc)
file (GLOB docs RELATIVE ${CMAKE_CURRENT_BINARY_DIR}/ "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.txt")
set (html-docs)
foreach (txt ${docs})
  string (REGEX REPLACE ".*/(.*)\\.txt" "\\1.html" html ${txt})
  set (src ${txt})
  set (dst doc/${html})
  add_custom_command (
    OUTPUT  ${dst}
    COMMAND ${PYTHON_EXECUTABLE}
    ARGS    -x
    ${ASCIIDOC_EXECUTABLE}
    -d manpage
    -b xhtml11
    -f ${CMAKE_CURRENT_SOURCE_DIR}/doc/asciidoc.conf
    -azmq_version=${ZMQ_VERSION}
    -o ${dst}
    ${src}
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${src}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating ${html}")
  if (WITH_DOC)
    list (APPEND html-docs ${CMAKE_CURRENT_BINARY_DIR}/${dst})
  endif ()
endforeach ()

if (ZMQ_BUILD_FRAMEWORK)
  add_custom_command (
    TARGET libzmq
    POST_BUILD
    COMMAND ${CMAKE_COMMAND}
    ARGS -E make_directory "${CMAKE_LIBRARY_OUTPUT_PATH}/ZeroMQ.framework/Versions/${ZMQ_VERSION}/MacOS"
    COMMENT "Perf tools")
endif ()

if (MSVC)
    # default for all sources is to use precompiled headers
    foreach(source ${sources})
        set_source_files_properties(${source}
            PROPERTIES
            COMPILE_FLAGS "/Yuprecompiled.hpp"
            )
    endforeach()
    # create precompiled header
    set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/src/precompiled.cpp
        PROPERTIES
        COMPILE_FLAGS "/Ycprecompiled.hpp"
        )
    # C and C++ can not use the same precompiled header
    set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/src/tweetnacl.c
        PROPERTIES
        COMPILE_FLAGS "/Y-"
        )
endif ()


#-----------------------------------------------------------------------------
# output

if (MSVC)
  add_library (libzmq SHARED ${sources} ${public_headers} ${html-docs} ${readme-docs} ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in)
  target_link_libraries (libzmq ${OPTIONAL_LIBRARIES})
  set_target_properties (libzmq PROPERTIES
    PUBLIC_HEADER "${public_headers}"
    RELEASE_POSTFIX "${MSVC_TOOLSET}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    RELWITHDEBINFO_POSTFIX "${MSVC_TOOLSET}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    DEBUG_POSTFIX "${MSVC_TOOLSET}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin"
    COMPILE_DEFINITIONS "DLL_EXPORT")
  add_library (libzmq-static STATIC ${sources})
  set_target_properties (libzmq-static PROPERTIES
    PUBLIC_HEADER "${public_headers}"
    RELEASE_POSTFIX "${MSVC_TOOLSET}-mt-s-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    RELWITHDEBINFO_POSTFIX "${MSVC_TOOLSET}-mt-s-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    DEBUG_POSTFIX "${MSVC_TOOLSET}-mt-sgd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
    COMPILE_FLAGS "/DZMQ_STATIC"
    OUTPUT_NAME "libzmq")
else ()
    add_library (libzmq SHARED ${sources} ${public_headers} ${html-docs} ${readme-docs} ${zmq-pkgconfig})
    # NOTE: the SOVERSION MUST be the same as the one generated by libtool!
    set_target_properties (libzmq PROPERTIES
                          COMPILE_DEFINITIONS "DLL_EXPORT"
                          PUBLIC_HEADER "${public_headers}"
                          VERSION ${ZMQ_VERSION}
                          SOVERSION "5.1.3"
                          OUTPUT_NAME "libzmq"
                          PREFIX "")
    if (ZMQ_BUILD_FRAMEWORK)
      set_target_properties (libzmq PROPERTIES
                            FRAMEWORK TRUE
                            MACOSX_FRAMEWORK_IDENTIFIER "org.zeromq.libzmq"
                            MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${ZMQ_VERSION}
                            MACOSX_FRAMEWORK_BUNDLE_VERSION ${ZMQ_VERSION})
      set_source_files_properties (${html-docs} PROPERTIES
                                  MACOSX_PACKAGE_LOCATION doc)
      set_source_files_properties (${readme-docs} PROPERTIES
                                  MACOSX_PACKAGE_LOCATION etc)
      set_source_files_properties (${zmq-pkgconfig} PROPERTIES
                                  MACOSX_PACKAGE_LOCATION lib/pkgconfig)
    endif ()
    add_library (libzmq-static STATIC ${sources} ${public_headers} ${html-docs} ${readme-docs} ${zmq-pkgconfig})
    set_target_properties (libzmq-static PROPERTIES
      PUBLIC_HEADER "${public_headers}"
      COMPILE_DEFINITIONS "ZMQ_STATIC"
      OUTPUT_NAME "libzmq"
      PREFIX "")
endif ()

target_link_libraries (libzmq ${CMAKE_THREAD_LIBS_INIT})

if (SODIUM_FOUND)
  target_link_libraries (libzmq ${SODIUM_LIBRARIES})
endif ()
if (HAVE_WS2_32)
  target_link_libraries (libzmq ws2_32)
elseif (HAVE_WS2)
  target_link_libraries (libzmq ws2)
endif ()

if (HAVE_RPCRT4)
  target_link_libraries (libzmq rpcrt4)
endif ()

if (HAVE_IPHLAPI)
  target_link_libraries (libzmq iphlpapi)
endif ()

if (RT_LIBRARY)
  target_link_libraries (libzmq ${RT_LIBRARY})
endif ()

set (perf-tools local_lat
               remote_lat
               local_thr
               remote_thr
               inproc_lat
               inproc_thr)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug") # Why?
option (WITH_PERF_TOOL "Build with perf-tools" ON)
else ()
option (WITH_PERF_TOOL "Build with perf-tools" OFF)
endif ()

if (WITH_PERF_TOOL)
  foreach (perf-tool ${perf-tools})
    add_executable (${perf-tool} perf/${perf-tool}.cpp)
    target_link_libraries (${perf-tool} libzmq ${OPTIONAL_LIBRARIES})

    if (RT_LIBRARY)
      target_link_libraries (${perf-tool} ${RT_LIBRARY})
    endif ()

    if (ZMQ_BUILD_FRAMEWORK)
      # Copy perf-tools binaries into Framework
      add_custom_command (
        TARGET libzmq ${perf-tool}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS -E copy "$<TARGET_FILE:${perf-tool}>" "${LIBRARY_OUTPUT_PATH}/ZeroMQ.framework/Versions/${ZMQ_VERSION_STRING}/MacOS/${perf-tool}"
        VERBATIM
        COMMENT "Perf tools")
    else ()
      install (TARGETS ${perf-tool}
              RUNTIME DESTINATION bin
              COMPONENT PerfTools)
    endif ()
  endforeach ()
endif ()

#-----------------------------------------------------------------------------
# tests

set (ZMQ_BUILD_TESTS ON CACHE BOOL "Build the tests for ZeroMQ")

if (ZMQ_BUILD_TESTS)
  enable_testing () # Enable testing only works in root scope
  ADD_SUBDIRECTORY (tests)
endif ()

#-----------------------------------------------------------------------------
# installer

include(GNUInstallDirs)

if (MSVC)
  install (TARGETS libzmq libzmq-static
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          COMPONENT SDK)
  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    install (TARGETS libzmq libzmq-static
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            COMPONENT SDK)
    if (NOT CMAKE_PDB_OUTPUT_DIRECTORY)
      install (FILES ${CMAKE_CURRENT_BINARY_DIR}/bin/libzmq${MSVC_TOOLSET}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}.pdb DESTINATION lib
            COMPONENT SDK)
    endif ()
  else ()
    install (TARGETS libzmq
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            COMPONENT Runtime)
  endif ()
else ()
  install (TARGETS libzmq libzmq-static
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
          FRAMEWORK DESTINATION "Library/Frameworks"
          PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif ()

# install (FILES ${public_headers}
#          DESTINATION include
#          COMPONENT SDK)

#if (NOT ZMQ_BUILD_FRAMEWORK)
#  file (GLOB private_headers "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp")
#  install (FILES ${sources} ${private_headers} DESTINATION src/zmq
#          COMPONENT SourceCode)
#endif ()

foreach (readme ${readme-docs})
  configure_file (${CMAKE_CURRENT_SOURCE_DIR}/${readme} ${CMAKE_CURRENT_BINARY_DIR}/${readme}.txt)

  if (NOT ZMQ_BUILD_FRAMEWORK)
    install (FILES ${CMAKE_CURRENT_BINARY_DIR}/${readme}.txt DESTINATION share/zmq)
  endif ()
endforeach ()

if (WITH_DOC)
  if (NOT ZMQ_BUILD_FRAMEWORK)
    install (FILES ${html-docs} DESTINATION doc/zmq COMPONENT RefGuide)
  endif ()
endif ()

include(CMakePackageConfigHelpers)

if (MSVC)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" U_CMAKE_BUILD_TYPE)
  get_property(libzmq_pf TARGET libzmq PROPERTY ${U_CMAKE_BUILD_TYPE}_POSTFIX)
  set(libzmq_file libzmq${libzmq_pf}${CMAKE_LINK_LIBRARY_SUFFIX})
  get_property(libzmq_static_pf TARGET libzmq-static PROPERTY ${U_CMAKE_BUILD_TYPE}_POSTFIX)
  set(libzmq_static_file libzmq${libzmq_static_pf}${CMAKE_LINK_LIBRARY_SUFFIX})
else()
  set(libzmq_file libzmq${CMAKE_SHARED_LIBRARY_SUFFIX})
  set(libzmq_static_file libzmq${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

# GNUInstallDirs "DATADIR" wrong here; CMake search path wants "share".
set(ZEROMQ_CMAKECONFIG_INSTALL_DIR "share/cmake/${PROJECT_NAME}" CACHE STRING "install path for ZeroMQConfig.cmake")

configure_package_config_file(${PROJECT_NAME}Config.cmake.in
                              "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
                              INSTALL_DESTINATION ${ZEROMQ_CMAKECONFIG_INSTALL_DIR})
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
                                 VERSION ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}
                                 COMPATIBILITY AnyNewerVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
              DESTINATION ${ZEROMQ_CMAKECONFIG_INSTALL_DIR})

option(ENABLE_CPACK "Enables cpack rules" ON)
if (MSVC AND ENABLE_CPACK)
  include (InstallRequiredSystemLibraries)

  if (CMAKE_CL_64)
    set (arch_name "x64")
  else ()
    set (arch_name "x86")
  endif ()

  set (CPACK_NSIS_DISPLAY_NAME "ZeroMQ ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH} (${arch_name})")
  set (CPACK_PACKAGE_FILE_NAME "ZeroMQ-${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}-${arch_name}")

  # TODO: I think this part was intended to be used when running cpack
  # separately from cmake but I don't know how that works.
  #
  # macro (add_crt_version version)
  #   set (rel_dir "${CMAKE_CURRENT_BINARY_DIR}/build/${arch_name}/${version};ZeroMQ;ALL;/")
  #   set (debug_dir "${CMAKE_CURRENT_BINARY_DIR}/debug/${arch_name}/${version};ZeroMQ;ALL;/")
  #   if (EXISTS ${rel_dir})
  #     list (APPEND CPACK_INSTALL_CMAKE_PROJECTS ${rel_dir})
  #   endif ()

  #   if (EXISTS ${debug_dir})
  #     list (APPEND CPACK_INSTALL_CMAKE_PROJECTS ${rel_dir})
  #   endmacro ()
  # endmacro ()

  # add_crt_version (v110)
  # add_crt_version (v100)
  # add_crt_version (v90)

  set (CMAKE_MODULE_PATH "${CMAKE_CURRENT_BINARY_DIR}")
  set (CPACK_GENERATOR "NSIS")
  set (CPACK_PACKAGE_NAME "ZeroMQ")
  set (CPACK_PACKAGE_DESCRIPTION_SUMMARY "ZeroMQ lightweight messaging kernel")
  set (CPACK_PACKAGE_VENDOR "Miru")
  set (CPACK_NSIS_CONTACT "Steven McCoy <Steven.McCoy@miru.hk>")
  set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}\\\\COPYING.txt")
#  set (CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_BINARY_DIR}\\\\README.txt")
#  set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_CURRENT_BINARY_DIR}\\\\WELCOME.txt")
  # There is a bug in NSI that does not handle full unix paths properly. Make
  # sure there is at least one set of four (4) backslashes.
  set (CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\installer.ico")
  set (CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\installer.ico")

  set (CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\branding.bmp")
  set (CPACK_NSIS_COMPRESSOR "/SOLID lzma")
  set (CPACK_PACKAGE_VERSION ${ZMQ_VERSION})
  set (CPACK_PACKAGE_VERSION_MAJOR ${ZMQ_VERSION_MAJOR})
  set (CPACK_PACKAGE_VERSION_MINOR ${ZMQ_VERSION_MINOR})
  set (CPACK_PACKAGE_VERSION_PATCH ${ZMQ_VERSION_PATCH})
#  set (CPACK_PACKAGE_INSTALL_DIRECTORY "ZMQ Install Directory")
#  set (CPACK_TEMPORARY_DIRECTORY "ZMQ Temporary CPack Directory")

  include (CPack)

  cpack_add_component_group (Development
    DISPLAY_NAME "ZeroMQ software development kit"
    EXPANDED)
  cpack_add_component (PerfTools
    DISPLAY_NAME "ZeroMQ performance tools"
    INSTALL_TYPES FullInstall DevInstall)
  cpack_add_component (SourceCode
    DISPLAY_NAME "ZeroMQ source code"
    DISABLED
    INSTALL_TYPES FullInstall)
  cpack_add_component (SDK
    DISPLAY_NAME "ZeroMQ headers and libraries"
    INSTALL_TYPES FullInstall DevInstall
    GROUP Development)
  if (WITH_DOC)
    cpack_add_component (RefGuide
      DISPLAY_NAME "ZeroMQ reference guide"
      INSTALL_TYPES FullInstall DevInstall
      GROUP Development)
  endif ()
  cpack_add_component (Runtime
    DISPLAY_NAME "ZeroMQ runtime files"
    REQUIRED
    INSTALL_TYPES FullInstall DevInstall MinInstall)
  cpack_add_install_type (FullInstall
    DISPLAY_NAME "Full install, including source code")
  cpack_add_install_type (DevInstall
    DISPLAY_NAME "Developer install, headers and libraries")
  cpack_add_install_type (MinInstall
    DISPLAY_NAME "Minimal install, runtime only")
endif ()

# Export this for library to help build this as a sub-project
set (ZEROMQ_LIBRARY libzmq CACHE STRING "ZeroMQ library")

# Workaround for MSVS10 to avoid the Dialog Hell
# FIXME: This could be removed with future version of CMake.
if (MSVC_VERSION EQUAL 1600)
  set (ZMQ_SLN_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/ZeroMQ.sln")
  if (EXISTS "${ZMQ_SLN_FILENAME}")
    file (APPEND "${ZMQ_SLN_FILENAME}" "\n# This should be regenerated!\n")
  endif ()
endif ()
