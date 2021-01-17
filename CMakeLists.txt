# CMake build script for ZeroMQ
project(ZeroMQ)

if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
  cmake_minimum_required(VERSION 3.0.2)
else()
  cmake_minimum_required(VERSION 2.8.12)
endif()

include(CheckIncludeFiles)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLibraryExists)
include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CMakeDependentOption)
include(CheckCXXSymbolExists)
include(CheckTypeSize)
include(FindThreads)
include(GNUInstallDirs)
include(CheckTypeSize)
include(CMakePackageConfigHelpers)

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}")
set(ZMQ_CMAKE_MODULES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/Modules)
list(APPEND CMAKE_MODULE_PATH ${ZMQ_CMAKE_MODULES_DIR})

include(TestZMQVersion)
include(ZMQSourceRunChecks)
include(ZMQSupportMacros)

find_package(PkgConfig)

# Set lists to empty beforehand as to not accidentally take values from parent
set(sources)
set(cxx-sources)
set(html-docs)
set(target_outputs)

option(ENABLE_ASAN "Build with address sanitizer" OFF)
if(ENABLE_ASAN)
  message(STATUS "Instrumenting with Address Sanitizer")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope -fno-omit-frame-pointer")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -fsanitize-address-use-after-scope")
endif()

# NOTE: Running libzmq under TSAN doesn't make much sense -- synchronization in libzmq is to some extent
# handled by the code "knowing" what threads are allowed to do, rather than by enforcing those
# restrictions, so TSAN generates a lot of (presumably) false positives from libzmq.
# The settings below are intended to enable libzmq to be built with minimal support for TSAN
# such that it can be used along with other code that is also built with TSAN.
option(ENABLE_TSAN "Build with thread sanitizer" OFF)
if(ENABLE_TSAN)
  message(STATUS "Instrumenting with Thread Sanitizer")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  set(TSAN_FLAGS "-fno-omit-frame-pointer -fsanitize=thread")
  set(TSAN_CCFLAGS "${TSAN_CCFLAGS} -mllvm -tsan-instrument-memory-accesses=0")
  set(TSAN_CCFLAGS "${TSAN_CCFLAGS} -mllvm -tsan-instrument-atomics=0")
  set(TSAN_CCFLAGS "${TSAN_CCFLAGS} -mllvm -tsan-instrument-func-entry-exit=1")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TSAN_FLAGS} ${TSAN_CCFLAGS} -fPIE")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TSAN_FLAGS} ${TSAN_CCFLAGS} -fPIE")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${TSAN_FLAGS} -pie -Qunused-arguments")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${TSAN_FLAGS} -pie -Qunused-arguments")
endif()

option(ENABLE_UBSAN "Build with undefined behavior sanitizer" OFF)
if(ENABLE_UBSAN)
  message(STATUS "Instrumenting with Undefined Behavior Sanitizer")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fno-omit-frame-pointer")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=undefined")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=implicit-conversion")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=implicit-integer-truncation")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=integer")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=nullability")
  set(UBSAN_FLAGS "${UBSAN_FLAGS} -fsanitize=vptr")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${UBSAN_FLAGS}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${UBSAN_FLAGS}")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${UBSAN_FLAGS}")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${UBSAN_FLAGS}")
endif()

option(ENABLE_INTRINSICS "Build using compiler intrinsics for atomic ops" OFF)
if(ENABLE_INTRINSICS)
  message(STATUS "Using compiler intrinsics for atomic ops")
  add_definitions(-DZMQ_HAVE_ATOMIC_INTRINSICS)
endif()

set(ZMQ_OUTPUT_BASENAME
    "zmq"
    CACHE STRING "Output zmq library base name")

if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
  # Find more information: https://cmake.org/Wiki/CMake_RPATH_handling

  # Apply CMP0042: MACOSX_RPATH is enabled by default
  cmake_policy(SET CMP0042 NEW)

  # Add an install rpath if it is not a system directory
  list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}" isSystemDir)
  if("${isSystemDir}" STREQUAL "-1")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  endif()

  # Add linker search paths pointing to external dependencies
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
endif()

if (NOT MSVC)
  if(NOT CMAKE_CXX_FLAGS MATCHES "-std=")
    # use C++11 by default if supported
    check_cxx_compiler_flag("-std=gnu++11" COMPILER_SUPPORTS_CXX11)
    if(COMPILER_SUPPORTS_CXX11)
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")
    endif()
  endif()
  if(NOT CMAKE_C_FLAGS MATCHES "-std=")
    check_c_compiler_flag("-std=gnu11" COMPILER_SUPPORTS_C11)
    if(COMPILER_SUPPORTS_C11)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")
    else()
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
    endif()
  endif()

  # clang 6 has a warning that does not make sense on multi-platform code
  check_cxx_compiler_flag("-Wno-tautological-constant-compare" CXX_HAS_TAUT_WARNING)
  if(CXX_HAS_TAUT_WARNING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-tautological-constant-compare")
  endif()
  check_c_compiler_flag("-Wno-tautological-constant-compare" CC_HAS_TAUT_WARNING)
  if(CC_HAS_TAUT_WARNING)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-tautological-constant-compare")
  endif()
endif()

# Will be used to add flags to pkg-config useful when apps want to statically link
set(pkg_config_libs_private "")
set(pkg_config_names_private "")

option(WITH_OPENPGM "Build with support for OpenPGM" OFF)
option(WITH_NORM "Build with support for NORM" OFF)
option(WITH_VMCI "Build with support for VMware VMCI socket" OFF)

if(APPLE)
  option(ZMQ_BUILD_FRAMEWORK "Build as OS X framework" OFF)
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
  message(STATUS "Build and install draft classes and methods")
  option(ENABLE_DRAFTS "Build and install draft classes and methods" ON)
else()
  message(STATUS "Not building draft classes and methods")
  option(ENABLE_DRAFTS "Build and install draft classes and methods" OFF)
endif()

# Enable WebSocket transport and RadixTree
if(ENABLE_DRAFTS)
  set(ZMQ_BUILD_DRAFT_API 1)
  option(ENABLE_WS "Enable WebSocket transport" ON)
  option(ENABLE_RADIX_TREE "Use radix tree implementation to manage subscriptions" ON)
else()
  option(ENABLE_WS "Enable WebSocket transport" OFF)
  option(ENABLE_RADIX_TREE "Use radix tree implementation to manage subscriptions" OFF)
endif()

if(ENABLE_RADIX_TREE)
  message(STATUS "Using radix tree implementation to manage subscriptions")
  set(ZMQ_USE_RADIX_TREE 1)
endif()

if(ENABLE_WS)
  list(
    APPEND
    sources
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_address.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_connecter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_decoder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_encoder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_engine.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_listener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_address.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_connecter.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_decoder.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_encoder.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_engine.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_listener.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ws_protocol.hpp)
  set(ZMQ_HAVE_WS 1)

  message(STATUS "Enable WebSocket transport")

  option(WITH_TLS "Use TLS for WSS support" ON)
  option(WITH_NSS "Use NSS instead of builtin sha1" OFF)

  if(WITH_TLS)
    find_package("GnuTLS" 3.6.7)
    if(GNUTLS_FOUND)
      set(pkg_config_names_private "${pkg_config_names_private} gnutls")
      list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/src/wss_address.hpp
           ${CMAKE_CURRENT_SOURCE_DIR}/src/wss_address.cpp ${CMAKE_CURRENT_SOURCE_DIR}/src/wss_engine.hpp
           ${CMAKE_CURRENT_SOURCE_DIR}/src/wss_engine.cpp)

      message(STATUS "Enable WSS transport")
      set(ZMQ_USE_GNUTLS 1)
      set(ZMQ_HAVE_WSS 1)
    else()
      message(WARNING "No WSS support, you may want to install GnuTLS and run cmake again")
    endif()
  endif()
endif()

if(NOT ZMQ_USE_GNUTLS)
  if(WITH_NSS)
    pkg_check_modules(NSS3 "nss")
    if(NSS3_FOUND)
      set(pkg_config_names_private "${pkg_config_names_private} nss")
      message(STATUS "Using NSS")
      set(ZMQ_USE_NSS 1)
    else()
      find_package("NSS3")
      if(NSS3_FOUND)
        set(pkg_config_libs_private "${pkg_config_libs_private} -lnss3")
        message(STATUS "Using NSS")
        set(ZMQ_USE_NSS 1)
      else()
        message(WARNING "No nss installed, if you don't want builtin SHA1, install NSS or GnuTLS")
      endif()
    endif()
  endif()
  if(NOT ZMQ_USE_NSS)
    list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/external/sha1/sha1.c
         ${CMAKE_CURRENT_SOURCE_DIR}/external/sha1/sha1.h)
    message(STATUS "Using builtin sha1")
    set(ZMQ_USE_BUILTIN_SHA1 1)
  endif()
endif()

if(NOT MSVC)
  option(WITH_LIBBSD "Use libbsd instead of builtin strlcpy" ON)
  if(WITH_LIBBSD)
    pkg_check_modules(LIBBSD "libbsd")
    if(LIBBSD_FOUND)
      message(STATUS "Using libbsd")
      set(pkg_config_names_private "${pkg_config_names_private} libbsd")
      set(ZMQ_HAVE_LIBBSD 1)
    endif()
  endif()
  check_cxx_symbol_exists(strlcpy string.h ZMQ_HAVE_STRLCPY)
endif()

# Select curve encryption library, defaults to tweetnacl To use libsodium instead, use --with-libsodium(must be
# installed) To disable curve, use --disable-curve

option(WITH_LIBSODIUM "Use libsodium instead of built-in tweetnacl" ON)
option(WITH_LIBSODIUM_STATIC "Use static libsodium library" OFF)
option(ENABLE_CURVE "Enable CURVE security" ON)

if(ENABLE_CURVE)
  if(WITH_LIBSODIUM)
    find_package("Sodium")
    if(SODIUM_FOUND)
      message(STATUS "Using libsodium for CURVE security")
      include_directories(${SODIUM_INCLUDE_DIRS})
      if(WITH_LIBSODIUM_STATIC)
        add_compile_definitions(SODIUM_STATIC)
      endif()
      set(ZMQ_USE_LIBSODIUM 1)
      set(ZMQ_HAVE_CURVE 1)
    else()
      message(
        WARNING
          "libsodium not installed, instead using builtin tweetnacl, you may want to install libsodium and run cmake again"
      )
    endif()
  endif()
  if(NOT ZMQ_HAVE_CURVE)
    message(STATUS "Using tweetnacl for CURVE security")
    list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/src/tweetnacl.c)
    set(ZMQ_USE_TWEETNACL 1)
    set(ZMQ_HAVE_CURVE 1)
  endif()
else()
  message(STATUS "CURVE security is disabled")
endif()

set(SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

option(WITH_MILITANT "Enable militant assertions" OFF)
if(WITH_MILITANT)
  add_definitions(-DZMQ_ACT_MILITANT)
endif()

set(API_POLLER
    ""
    CACHE STRING "Choose polling system for zmq_poll(er)_*. valid values are
  poll or select [default=poll unless POLLER=select]")

set(POLLER
    ""
    CACHE STRING "Choose polling system for I/O threads. valid values are
  kqueue, epoll, devpoll, pollset, poll or select [default=autodetect]")

if(WIN32)
  if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore" AND CMAKE_SYSTEM_VERSION MATCHES "^10.0")
    set(ZMQ_HAVE_WINDOWS_UWP ON)
    set(ZMQ_HAVE_IPC OFF)
    # to remove compile warninging "D9002 ignoring unknown option"
    string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    set(CMAKE_CXX_FLAGS_DEBUG
        ${CMAKE_CXX_FLAGS_DEBUG}
        CACHE STRING "" FORCE)
    string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO ${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO
        ${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
        CACHE STRING "" FORCE)
    string(REPLACE "/Zi" "" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
  endif()
  # from https://stackoverflow.com/a/40217291/2019765
  macro(get_WIN32_WINNT version)
    if(CMAKE_SYSTEM_VERSION)
      set(ver ${CMAKE_SYSTEM_VERSION})
      string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
      string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
      # Check for Windows 10, b/c we'll need to convert to hex 'A'.
      if("${verMajor}" MATCHES "10")
        set(verMajor "A")
        string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
      endif("${verMajor}" MATCHES "10")
      # Remove all remaining '.' characters.
      string(REPLACE "." "" ver ${ver})
      # Prepend each digit with a zero.
      string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
      set(${version} "0x${ver}")
    endif(CMAKE_SYSTEM_VERSION)
  endmacro(get_WIN32_WINNT)

  get_win32_winnt(ZMQ_WIN32_WINNT_DEFAULT)
  message(STATUS "Detected _WIN32_WINNT from CMAKE_SYSTEM_VERSION: ${ZMQ_WIN32_WINNT_DEFAULT}")

  # TODO limit _WIN32_WINNT to the actual Windows SDK version, which might be different from the default version
  # installed with Visual Studio
  if(MSVC_VERSION STREQUAL "1500" AND CMAKE_SYSTEM_VERSION VERSION_GREATER "6.0")
    set(ZMQ_WIN32_WINNT_LIMIT "0x0600")
  elseif(MSVC_VERSION STREQUAL "1600" AND CMAKE_SYSTEM_VERSION VERSION_GREATER "6.1")
    set(ZMQ_WIN32_WINNT_LIMIT "0x0601")
  elseif(MSVC_VERSION STREQUAL "1700" AND CMAKE_SYSTEM_VERSION VERSION_GREATER "6.1")
    set(ZMQ_WIN32_WINNT_LIMIT "0x0601")
  elseif(MSVC_VERSION STREQUAL "1800" AND CMAKE_SYSTEM_VERSION VERSION_GREATER "6.2")
    set(ZMQ_WIN32_WINNT_LIMIT "0x0602")
  endif()
  if(ZMQ_WIN32_WINNT_LIMIT)
    message(
      STATUS
        "Mismatch of Visual Studio Version (${MSVC_VERSION}) and CMAKE_SYSTEM_VERSION (${CMAKE_SYSTEM_VERSION}), limiting _WIN32_WINNT to ${ZMQ_WIN32_WINNT_LIMIT}, you may override this by setting ZMQ_WIN32_WINNT"
    )
    set(ZMQ_WIN32_WINNT_DEFAULT "${ZMQ_WIN32_WINNT_LIMIT}")
  endif()

  set(ZMQ_WIN32_WINNT
      "${ZMQ_WIN32_WINNT_DEFAULT}"
      CACHE STRING "Value to set _WIN32_WINNT to for building [default=autodetect from build environment]")

  # On Windows Vista or greater, with MSVC 2013 or greater, default to epoll (which is required on Win 10 for ipc
  # support)
  if(ZMQ_WIN32_WINNT GREATER "0x05FF"
     AND MSVC_VERSION GREATER 1799
     AND POLLER STREQUAL ""
     AND NOT ZMQ_HAVE_WINDOWS_UWP)
    set(POLLER "epoll")
  endif()

  add_definitions(-D_WIN32_WINNT=${ZMQ_WIN32_WINNT})
endif(WIN32)

if(NOT MSVC)
  if(POLLER STREQUAL "")
    check_cxx_symbol_exists(kqueue sys/event.h HAVE_KQUEUE)
    if(HAVE_KQUEUE)
      set(POLLER "kqueue")
    endif()
  endif()

  if(POLLER STREQUAL "")
    check_cxx_symbol_exists(epoll_create sys/epoll.h HAVE_EPOLL)
    if(HAVE_EPOLL)
      set(POLLER "epoll")
      check_cxx_symbol_exists(epoll_create1 sys/epoll.h HAVE_EPOLL_CLOEXEC)
      if(HAVE_EPOLL_CLOEXEC)
        set(ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC 1)
      endif()
    endif()
  endif()

  if(POLLER STREQUAL "")
    set(CMAKE_EXTRA_INCLUDE_FILES sys/devpoll.h)
    check_type_size("struct pollfd" DEVPOLL)
    set(CMAKE_EXTRA_INCLUDE_FILES)
    if(HAVE_DEVPOLL)
      set(POLLER "devpoll")
    endif()
  endif()

  if(POLLER STREQUAL "")
    check_cxx_symbol_exists(pollset_create sys/pollset.h HAVE_POLLSET)
    if(HAVE_POLLSET)
      set(POLLER "pollset")
    endif()
  endif()

  if(POLLER STREQUAL "")
    check_cxx_symbol_exists(poll poll.h HAVE_POLL)
    if(HAVE_POLL)
      set(POLLER "poll")
    endif()
  endif()
endif()

if(POLLER STREQUAL "")
  if(WIN32)
    set(HAVE_SELECT 1)
  else()
    check_cxx_symbol_exists(select sys/select.h HAVE_SELECT)
  endif()
  if(HAVE_SELECT)
    set(POLLER "select")
  else()
    message(FATAL_ERROR "Could not autodetect polling method")
  endif()
endif()

if(POLLER STREQUAL "kqueue"
   OR POLLER STREQUAL "epoll"
   OR POLLER STREQUAL "devpoll"
   OR POLLER STREQUAL "pollset"
   OR POLLER STREQUAL "poll"
   OR POLLER STREQUAL "select")
  message(STATUS "Using polling method in I/O threads: ${POLLER}")
  string(TOUPPER ${POLLER} UPPER_POLLER)
  set(ZMQ_IOTHREAD_POLLER_USE_${UPPER_POLLER} 1)
else()
  message(FATAL_ERROR "Invalid polling method")
endif()

if(POLLER STREQUAL "epoll" AND WIN32)
  message(STATUS "Including wepoll")
  list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/external/wepoll/wepoll.c
       ${CMAKE_CURRENT_SOURCE_DIR}/external/wepoll/wepoll.h)
endif()

if(API_POLLER STREQUAL "")
  if(POLLER STREQUAL "select")
    set(API_POLLER "select")
  else()
    set(API_POLLER "poll")
  endif()
endif()

message(STATUS "Using polling method in zmq_poll(er)_* API: ${API_POLLER}")
string(TOUPPER ${API_POLLER} UPPER_API_POLLER)
set(ZMQ_POLL_BASED_ON_${UPPER_API_POLLER} 1)

execute_process(
  COMMAND getconf LEVEL1_DCACHE_LINESIZE
  OUTPUT_VARIABLE CACHELINE_SIZE
  ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
if(CACHELINE_SIZE STREQUAL ""
   OR CACHELINE_SIZE EQUAL 0
   OR CACHELINE_SIZE EQUAL -1)
  set(ZMQ_CACHELINE_SIZE 64)
else()
  set(ZMQ_CACHELINE_SIZE ${CACHELINE_SIZE})
endif()
message(STATUS "Using ${ZMQ_CACHELINE_SIZE} bytes alignment for lock-free data structures")

if(NOT CYGWIN)
  # TODO cannot we simply do 'if(WIN32) set(ZMQ_HAVE_WINDOWS ON)' or similar?
  check_include_files(windows.h ZMQ_HAVE_WINDOWS)
endif()

if(NOT WIN32)
  set(ZMQ_HAVE_IPC 1)
else()
  check_include_files("winsock2.h;afunix.h" ZMQ_HAVE_IPC)
endif()

# ##################### BEGIN condition_variable_t selection
if(NOT ZMQ_CV_IMPL)
  # prefer C++11 STL std::condition_variable implementation, if available
  check_include_files(condition_variable ZMQ_HAVE_STL_CONDITION_VARIABLE LANGUAGE CXX)

  if(ZMQ_HAVE_STL_CONDITION_VARIABLE)
    set(ZMQ_CV_IMPL_DEFAULT "stl11")
  else()
    if(WIN32 AND NOT CMAKE_SYSTEM_VERSION VERSION_LESS "6.0")
      # Win32API CONDITION_VARIABLE is supported from Windows Vista only
      set(ZMQ_CV_IMPL_DEFAULT "win32api")
    elseif(CMAKE_USE_PTHREADS_INIT)
      set(ZMQ_CV_IMPL_DEFAULT "pthreads")
    else()
      set(ZMQ_CV_IMPL_DEFAULT "none")
    endif()
  endif()

  # TODO a vxworks implementation also exists, but vxworks is not currently supported with cmake at all
  set(ZMQ_CV_IMPL
      "${ZMQ_CV_IMPL_DEFAULT}"
      CACHE STRING "Choose condition_variable_t implementation. Valid values are
       stl11, win32api, pthreads, none [default=autodetect]")
endif()

message(STATUS "Using condition_variable_t implementation: ${ZMQ_CV_IMPL}")
if(ZMQ_CV_IMPL STREQUAL "stl11")
  set(ZMQ_USE_CV_IMPL_STL11 1)
elseif(ZMQ_CV_IMPL STREQUAL "win32api")
  set(ZMQ_USE_CV_IMPL_WIN32API 1)
elseif(ZMQ_CV_IMPL STREQUAL "pthreads")
  set(ZMQ_USE_CV_IMPL_PTHREADS 1)
elseif(ZMQ_CV_IMPL STREQUAL "none")
  set(ZMQ_USE_CV_IMPL_NONE 1)
else()
  message(ERROR "Unknown value for ZMQ_CV_IMPL: ${ZMQ_CV_IMPL}")
endif()
# ##################### END condition_variable_t selection

if(NOT MSVC)
  check_include_files(ifaddrs.h ZMQ_HAVE_IFADDRS)
  check_include_files(sys/uio.h ZMQ_HAVE_UIO)
  check_include_files(sys/eventfd.h ZMQ_HAVE_EVENTFD)
  if(ZMQ_HAVE_EVENTFD AND NOT CMAKE_CROSSCOMPILING)
    zmq_check_efd_cloexec()
  endif()
endif()

if(ZMQ_HAVE_WINDOWS)
  # Cannot use check_library_exists because the symbol is always declared as char(*)(void)
  set(CMAKE_REQUIRED_LIBRARIES "ws2_32.lib")
  check_cxx_symbol_exists(WSAStartup "winsock2.h" HAVE_WS2_32)

  set(CMAKE_REQUIRED_LIBRARIES "rpcrt4.lib")
  check_cxx_symbol_exists(UuidCreateSequential "rpc.h" HAVE_RPCRT4)

  set(CMAKE_REQUIRED_LIBRARIES "iphlpapi.lib")
  check_cxx_symbol_exists(GetAdaptersAddresses "winsock2.h;iphlpapi.h" HAVE_IPHLAPI)
  check_cxx_symbol_exists(if_nametoindex "iphlpapi.h" HAVE_IF_NAMETOINDEX)

  set(CMAKE_REQUIRED_LIBRARIES "")
  # TODO: This not the symbol we're looking for. What is the symbol?
  check_library_exists(ws2 fopen "" HAVE_WS2)
else()
  check_cxx_symbol_exists(if_nametoindex net/if.h HAVE_IF_NAMETOINDEX)
  check_cxx_symbol_exists(SO_PEERCRED sys/socket.h ZMQ_HAVE_SO_PEERCRED)
  check_cxx_symbol_exists(LOCAL_PEERCRED sys/socket.h ZMQ_HAVE_LOCAL_PEERCRED)
endif()

if(NOT MINGW)
  find_library(RT_LIBRARY rt)
  if(RT_LIBRARY)
    set(pkg_config_libs_private "${pkg_config_libs_private} -lrt")
  endif()
endif()

find_package(Threads)

if(WIN32 AND NOT CYGWIN)
  if(NOT HAVE_WS2_32 AND NOT HAVE_WS2)
    message(FATAL_ERROR "Cannot link to ws2_32 or ws2")
  endif()

  if(NOT HAVE_RPCRT4)
    message(FATAL_ERROR "Cannot link to rpcrt4")
  endif()

  if(NOT HAVE_IPHLAPI)
    message(FATAL_ERROR "Cannot link to iphlapi")
  endif()
endif()

if(NOT MSVC)
  set(CMAKE_REQUIRED_LIBRARIES rt)
  check_cxx_symbol_exists(clock_gettime time.h HAVE_CLOCK_GETTIME)
  set(CMAKE_REQUIRED_LIBRARIES)

  check_cxx_symbol_exists(fork unistd.h HAVE_FORK)
  check_cxx_symbol_exists(gethrtime sys/time.h HAVE_GETHRTIME)
  check_cxx_symbol_exists(mkdtemp stdlib.h HAVE_MKDTEMP)
  check_cxx_symbol_exists(accept4 sys/socket.h HAVE_ACCEPT4)
  check_cxx_symbol_exists(strnlen string.h HAVE_STRNLEN)
else()
  set(HAVE_STRNLEN 1)
endif()

add_definitions(-D_REENTRANT -D_THREAD_SAFE)
add_definitions(-DZMQ_CUSTOM_PLATFORM_HPP)

option(ENABLE_EVENTFD "Enable/disable eventfd" ZMQ_HAVE_EVENTFD)

macro(zmq_check_cxx_flag_prepend flag)
  check_cxx_compiler_flag("${flag}" HAVE_FLAG_${flag})

  if(HAVE_FLAG_${flag})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${flag}")
  endif()
endmacro()

option(ENABLE_ANALYSIS "Build with static analysis(make take very long)" OFF)

if(MSVC)
  if(ENABLE_ANALYSIS)
    zmq_check_cxx_flag_prepend("/W4")

    zmq_check_cxx_flag_prepend("/analyze")

    # C++11/14/17-specific, but maybe possible via conditional defines
    zmq_check_cxx_flag_prepend("/wd26440") # Function '...' can be declared 'noexcept'
    zmq_check_cxx_flag_prepend("/wd26432") # If you define or delete any default operation in the type '...', define or
                                           # delete them all
    zmq_check_cxx_flag_prepend("/wd26439") # This kind of function may not throw. Declare it 'noexcept'
    zmq_check_cxx_flag_prepend("/wd26447") # The function is declared 'noexcept' but calls function '...' which may
                                           # throw exceptions
    zmq_check_cxx_flag_prepend("/wd26433") # Function '...' should be marked with 'override'
    zmq_check_cxx_flag_prepend("/wd26409") # Avoid calling new and delete explicitly, use std::make_unique<T> instead
    # Requires GSL
    zmq_check_cxx_flag_prepend("/wd26429") # Symbol '...' is never tested for nullness, it can be marked as not_null
    zmq_check_cxx_flag_prepend("/wd26446") # Prefer to use gsl::at()
    zmq_check_cxx_flag_prepend("/wd26481") # Don't use pointer arithmetic. Use span instead
    zmq_check_cxx_flag_prepend("/wd26472") # Don't use a static_cast for arithmetic conversions. Use brace
                                           # initialization, gsl::narrow_cast or gsl::narow
    zmq_check_cxx_flag_prepend("/wd26448") # Consider using gsl::finally if final action is intended
    zmq_check_cxx_flag_prepend("/wd26400") # Do not assign the result of an allocation or a function call with an
                                           # owner<T> return value to a raw pointer, use owner<T> instead
    zmq_check_cxx_flag_prepend("/wd26485") # Expression '...': No array to pointer decay(bounds.3)
  else()
    zmq_check_cxx_flag_prepend("/W3")
  endif()

  if(MSVC_IDE)
    set(MSVC_TOOLSET "-${CMAKE_VS_PLATFORM_TOOLSET}")
  else()
    set(MSVC_TOOLSET "")
  endif()
else()
  zmq_check_cxx_flag_prepend("-Wall")
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  zmq_check_cxx_flag_prepend("-Wextra")
endif()

option(LIBZMQ_PEDANTIC "" ON)
option(LIBZMQ_WERROR "" OFF)

# TODO: why is -Wno-long-long defined differently than in configure.ac?
if(NOT MSVC)
  zmq_check_cxx_flag_prepend("-Wno-long-long")
  zmq_check_cxx_flag_prepend("-Wno-uninitialized")

  if(LIBZMQ_PEDANTIC)
    zmq_check_cxx_flag_prepend("-pedantic")

    if(${CMAKE_CXX_COMPILER_ID} MATCHES "Intel")
      zmq_check_cxx_flag_prepend("-strict-ansi")
    endif()

    if(${CMAKE_CXX_COMPILER_ID} MATCHES "SunPro")
      zmq_check_cxx_flag_prepend("-compat=5")
    endif()
  endif()
endif()

if(LIBZMQ_WERROR)
  if(MSVC)
    zmq_check_cxx_flag_prepend("/WX")
  else()
    zmq_check_cxx_flag_prepend("-Werror")
    if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      zmq_check_cxx_flag_prepend("-errwarn=%all")
    endif()
  endif()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^sparc")
  zmq_check_cxx_flag_prepend("-mcpu=v9")
endif()

if(${CMAKE_CXX_COMPILER_ID} MATCHES "SunPro")
  zmq_check_cxx_flag_prepend("-features=zla")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "SunOS"
   OR CMAKE_SYSTEM_NAME MATCHES "NetBSD"
   OR CMAKE_SYSTEM_NAME MATCHES "QNX")
  message(STATUS "Checking whether atomic operations can be used")
  check_c_source_compiles(
    "\
  #include <atomic.h> \
  \
  int main() \
  { \
    uint32_t value; \
    atomic_cas_32(&value, 0, 0); \
    return 0; \
  } \
  "
    HAVE_ATOMIC_H)

  if(NOT HAVE_ATOMIC_H)
    set(ZMQ_FORCE_MUTEXES 1)
  endif()
endif()

if(NOT ANDROID)
  zmq_check_noexcept()
endif()

# -----------------------------------------------------------------------------
if(NOT CMAKE_CROSSCOMPILING AND NOT MSVC)
  zmq_check_sock_cloexec()
  zmq_check_o_cloexec()
  zmq_check_so_bindtodevice()
  zmq_check_so_keepalive()
  zmq_check_so_priority()
  zmq_check_tcp_keepcnt()
  zmq_check_tcp_keepidle()
  zmq_check_tcp_keepintvl()
  zmq_check_tcp_keepalive()
  zmq_check_tcp_tipc()
  zmq_check_pthread_setname()
  zmq_check_pthread_setaffinity()
  zmq_check_getrandom()
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux"
   OR CMAKE_SYSTEM_NAME MATCHES "GNU/kFreeBSD"
   OR CMAKE_SYSTEM_NAME MATCHES "GNU/Hurd"
   OR CYGWIN)
  add_definitions(-D_GNU_SOURCE)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  add_definitions(-D__BSD_VISIBLE)
elseif(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
  add_definitions(-D_NETBSD_SOURCE)
elseif(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  add_definitions(-D_OPENBSD_SOURCE)
elseif(CMAKE_SYSTEM_NAME MATCHES "SunOS")
  add_definitions(-D_PTHREADS)
elseif(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
  add_definitions(-D_POSIX_C_SOURCE=200112L)
  zmq_check_cxx_flag_prepend(-Ae)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  add_definitions(-D_DARWIN_C_SOURCE)
endif()

find_package(AsciiDoc)

cmake_dependent_option(WITH_DOC "Build Reference Guide documentation(requires DocBook)" ON "ASCIIDOC_FOUND;NOT WIN32"
                       OFF) # Do not build docs on Windows due to issues with symlinks

if(MSVC)
  if(WITH_OPENPGM)
    # set(OPENPGM_ROOT "" CACHE PATH "Location of OpenPGM")
    set(OPENPGM_VERSION_MAJOR 5)
    set(OPENPGM_VERSION_MINOR 2)
    set(OPENPGM_VERSION_MICRO 122)
    if(CMAKE_CL_64)
      find_path(
        OPENPGM_ROOT include/pgm/pgm.h
        PATHS
          "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
        NO_DEFAULT_PATH)
      message(STATUS "OpenPGM x64 detected - ${OPENPGM_ROOT}")
    else()
      find_path(
        OPENPGM_ROOT include/pgm/pgm.h
        PATHS
          "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
          "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Miru\\OpenPGM ${OPENPGM_VERSION_MAJOR}.${OPENPGM_VERSION_MINOR}.${OPENPGM_VERSION_MICRO}]"
          NO_DEFAULT_PATH)
      message(STATUS "OpenPGM x86 detected - ${OPENPGM_ROOT}")
    endif()
    set(OPENPGM_INCLUDE_DIRS ${OPENPGM_ROOT}/include)
    set(OPENPGM_LIBRARY_DIRS ${OPENPGM_ROOT}/lib)
    set(OPENPGM_LIBRARIES
        optimized
        libpgm${MSVC_TOOLSET}-mt-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib debug
        libpgm${MSVC_TOOLSET}-mt-gd-${OPENPGM_VERSION_MAJOR}_${OPENPGM_VERSION_MINOR}_${OPENPGM_VERSION_MICRO}.lib)
  endif()
else()
  if(WITH_OPENPGM)
    # message(FATAL_ERROR "WITH_OPENPGM not implemented")

    if(NOT OPENPGM_PKGCONFIG_NAME)
      set(OPENPGM_PKGCONFIG_NAME "openpgm-5.2")
    endif()

    set(OPENPGM_PKGCONFIG_NAME
        ${OPENPGM_PKGCONFIG_NAME}
        CACHE STRING "Name pkg-config shall use to find openpgm libraries and include paths" FORCE)

    pkg_check_modules(OPENPGM ${OPENPGM_PKGCONFIG_NAME})

    if(OPENPGM_FOUND)
      message(STATUS ${OPENPGM_PKGCONFIG_NAME}" found")
      set(pkg_config_names_private "${pkg_config_names_private} ${OPENPGM_PKGCONFIG_NAME}")
    else()
      message(
        FATAL_ERROR
          ${OPENPGM_PKGCONFIG_NAME}"  not found. openpgm is searchd via `pkg-config ${OPENPGM_PKGCONFIG_NAME}`. Consider providing a valid OPENPGM_PKGCONFIG_NAME"
      )
    endif()

    # DSO symbol visibility for openpgm
    if(HAVE_FLAG_VISIBILITY_HIDDEN)

    elseif(HAVE_FLAG_LDSCOPE_HIDDEN)

    endif()
  endif()
endif()

# -----------------------------------------------------------------------------
# force off-tree build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
  message(
    FATAL_ERROR
      "CMake generation is not allowed within the source directory! \
    Remove the CMakeCache.txt file and try again from another folder, e.g.: \
    \
      rm CMakeCache.txt \
      mkdir cmake-make \
      cd cmake-make \
      cmake ..")
endif()

# -----------------------------------------------------------------------------
# default to Release build

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  # CMAKE_BUILD_TYPE is not used for multi-configuration generators like Visual Studio/XCode which instead use
  # CMAKE_CONFIGURATION_TYPES
  set(CMAKE_BUILD_TYPE
      Release
      CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif()

# -----------------------------------------------------------------------------
# output directories

zmq_set_with_default(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${ZeroMQ_BINARY_DIR}/bin")
if(UNIX)
  set(zmq_library_directory "lib")
else()
  set(zmq_library_directory "bin")
endif()
zmq_set_with_default(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${ZeroMQ_BINARY_DIR}/${zmq_library_directory}")
zmq_set_with_default(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${ZeroMQ_BINARY_DIR}/lib")

# -----------------------------------------------------------------------------
# platform specifics

if(WIN32)
  # Socket limit is 16K(can be raised arbitrarily)
  add_definitions(-DFD_SETSIZE=16384)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

if(MSVC)
  # Parallel make.
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MP")

  # Compile the static lib with debug information included note: we assume here that the default flags contain some /Z
  # flag
  string(REGEX REPLACE "/Z.[^:]" "/Z7 " CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
  string(REGEX REPLACE "/Z.[^:]" "/Z7 " CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

  # Optimization flags. http://msdn.microsoft.com/en-us/magazine/cc301698.aspx
  if(NOT ${CMAKE_BUILD_TYPE} MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GL")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LTCG")
    set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /LTCG")
  endif()
endif()

# -----------------------------------------------------------------------------
# source files

set(cxx-sources
    precompiled.cpp
    address.cpp
    channel.cpp
    client.cpp
    clock.cpp
    ctx.cpp
    curve_mechanism_base.cpp
    curve_client.cpp
    curve_server.cpp
    dealer.cpp
    devpoll.cpp
    dgram.cpp
    dist.cpp
    endpoint.cpp
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
    mechanism_base.cpp
    metadata.cpp
    msg.cpp
    mtrie.cpp
    norm_engine.cpp
    object.cpp
    options.cpp
    own.cpp
    null_mechanism.cpp
    pair.cpp
    peer.cpp
    pgm_receiver.cpp
    pgm_sender.cpp
    pgm_socket.cpp
    pipe.cpp
    plain_client.cpp
    plain_server.cpp
    poll.cpp
    poller_base.cpp
    polling_util.cpp
    pollset.cpp
    proxy.cpp
    pub.cpp
    pull.cpp
    push.cpp
    random.cpp
    raw_encoder.cpp
    raw_decoder.cpp
    raw_engine.cpp
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
    stream_engine_base.cpp
    sub.cpp
    tcp.cpp
    tcp_address.cpp
    tcp_connecter.cpp
    tcp_listener.cpp
    thread.cpp
    trie.cpp
    radix_tree.cpp
    v1_decoder.cpp
    v1_encoder.cpp
    v2_decoder.cpp
    v2_encoder.cpp
    v3_1_encoder.cpp
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
    gather.cpp
    ip_resolver.cpp
    zap_client.cpp
    zmtp_engine.cpp
    # at least for VS, the header files must also be listed
    address.hpp
    array.hpp
    atomic_counter.hpp
    atomic_ptr.hpp
    blob.hpp
    channel.hpp
    client.hpp
    clock.hpp
    command.hpp
    compat.hpp
    condition_variable.hpp
    config.hpp
    ctx.hpp
    curve_client.hpp
    curve_client_tools.hpp
    curve_mechanism_base.hpp
    curve_server.hpp
    dbuffer.hpp
    dealer.hpp
    decoder.hpp
    decoder_allocators.hpp
    devpoll.hpp
    dgram.hpp
    dish.hpp
    dist.hpp
    encoder.hpp
    endpoint.hpp
    epoll.hpp
    err.hpp
    fd.hpp
    fq.hpp
    gather.hpp
    generic_mtrie.hpp
    generic_mtrie_impl.hpp
    gssapi_client.hpp
    gssapi_mechanism_base.hpp
    gssapi_server.hpp
    i_decoder.hpp
    i_encoder.hpp
    i_engine.hpp
    i_mailbox.hpp
    i_poll_events.hpp
    io_object.hpp
    io_thread.hpp
    ip.hpp
    ipc_address.hpp
    ipc_connecter.hpp
    ipc_listener.hpp
    kqueue.hpp
    lb.hpp
    likely.hpp
    macros.hpp
    mailbox.hpp
    mailbox_safe.hpp
    mechanism.hpp
    mechanism_base.hpp
    metadata.hpp
    msg.hpp
    mtrie.hpp
    mutex.hpp
    norm_engine.hpp
    null_mechanism.hpp
    object.hpp
    options.hpp
    own.hpp
    pair.hpp
    peer.hpp
    pgm_receiver.hpp
    pgm_sender.hpp
    pgm_socket.hpp
    pipe.hpp
    plain_client.hpp
    plain_common.hpp
    plain_server.hpp
    poll.hpp
    poller.hpp
    poller_base.hpp
    polling_util.hpp
    pollset.hpp
    precompiled.hpp
    proxy.hpp
    pub.hpp
    pull.hpp
    push.hpp
    radio.hpp
    random.hpp
    raw_decoder.hpp
    raw_encoder.hpp
    raw_engine.hpp
    reaper.hpp
    rep.hpp
    req.hpp
    router.hpp
    scatter.hpp
    secure_allocator.hpp
    select.hpp
    server.hpp
    session_base.hpp
    signaler.hpp
    socket_base.hpp
    socket_poller.hpp
    socks.hpp
    socks_connecter.hpp
    stdint.hpp
    stream.hpp
    stream_engine_base.hpp
    stream_connecter_base.hpp
    stream_connecter_base.cpp
    stream_listener_base.hpp
    stream_listener_base.cpp
    sub.hpp
    tcp.hpp
    tcp_address.hpp
    tcp_connecter.hpp
    tcp_listener.hpp
    thread.hpp
    timers.hpp
    tipc_address.hpp
    tipc_connecter.hpp
    tipc_listener.hpp
    trie.hpp
    udp_address.hpp
    udp_engine.hpp
    v1_decoder.hpp
    v1_encoder.hpp
    v2_decoder.hpp
    v2_encoder.hpp
    v3_1_encoder.hpp
    v2_protocol.hpp
    vmci.hpp
    vmci_address.hpp
    vmci_connecter.hpp
    vmci_listener.hpp
    windows.hpp
    wire.hpp
    xpub.hpp
    xsub.hpp
    ypipe.hpp
    ypipe_base.hpp
    ypipe_conflate.hpp
    yqueue.hpp
    zap_client.hpp
    zmtp_engine.hpp)

if(MINGW)
  # Generate the right type when using -m32 or -m64
  macro(set_rc_arch rc_target)
    set(CMAKE_RC_COMPILER_INIT windres)
    enable_language(RC)
    set(CMAKE_RC_COMPILE_OBJECT
        "<CMAKE_RC_COMPILER> <FLAGS> -O coff --target=${rc_target} <DEFINES> -i <SOURCE> -o <OBJECT>")
  endmacro()

  if(NOT CMAKE_SYSTEM_PROCESSOR)
    set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
  endif()

  # Also happens on x86_64 systems...what a worthless variable
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "i386"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "i486"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "i586"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "i686"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64"
     OR CMAKE_SYSTEM_PROCESSOR MATCHES "amd64")

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      set_rc_arch("pe-x86-64")
    else()
      set_rc_arch("pe-i386")
    endif()
  endif()
endif()

set(public_headers include/zmq.h include/zmq_utils.h)

set(readme-docs AUTHORS COPYING COPYING.LESSER NEWS)

# -----------------------------------------------------------------------------
# optional modules

if(WITH_OPENPGM)
  add_definitions(-DZMQ_HAVE_OPENPGM)
  include_directories(${OPENPGM_INCLUDE_DIRS})
  link_directories(${OPENPGM_LIBRARY_DIRS})
  set(OPTIONAL_LIBRARIES ${OPENPGM_LIBRARIES})
endif()

if(WITH_NORM)
  find_package(norm)
    if(norm_FOUND)
      message(STATUS "Building with NORM")
      set(ZMQ_HAVE_NORM 1)
    else()
      message(FATAL_ERROR "NORM not found")
    endif()
endif()

if(WITH_VMCI)
  add_definitions(-DZMQ_HAVE_VMCI)
  include_directories(${VMCI_INCLUDE_DIRS})
  list(APPEND cxx-sources vmci_address.cpp vmci_connecter.cpp vmci_listener.cpp vmci.cpp)
endif()

if(ZMQ_HAVE_TIPC)
  list(APPEND cxx-sources tipc_address.cpp tipc_connecter.cpp tipc_listener.cpp)
endif()

# -----------------------------------------------------------------------------
# source generators

foreach(source ${cxx-sources})
  list(APPEND sources ${CMAKE_CURRENT_SOURCE_DIR}/src/${source})
endforeach()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.rc.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc)

# Delete any src/platform.hpp left by configure
file(REMOVE ${CMAKE_CURRENT_SOURCE_DIR}/src/platform.hpp)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/platform.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/platform.hpp)
list(APPEND sources ${CMAKE_CURRENT_BINARY_DIR}/platform.hpp)

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix ${prefix})
set(libdir ${prefix}/lib)
set(includedir ${prefix}/include)
set(VERSION ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/libzmq.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc @ONLY)
set(zmq-pkgconfig ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc)

if(NOT ZMQ_BUILD_FRAMEWORK)
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libzmq.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()

if(MSVC)
  if(CMAKE_CL_64)
    set(nsis-template ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/NSIS.template64.in)
  else()
    set(nsis-template ${CMAKE_CURRENT_SOURCE_DIR}/builds/cmake/NSIS.template32.in)
  endif()

  add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in
    COMMAND ${CMAKE_COMMAND} ARGS -E copy ${nsis-template} ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in
    DEPENDS ${nsis-template})
endif()

option(WITH_DOCS "Build html docs" ON)
if(WITH_DOCS)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/doc)
  file(
    GLOB docs
    RELATIVE ${CMAKE_CURRENT_BINARY_DIR}/
    "${CMAKE_CURRENT_SOURCE_DIR}/doc/*.txt")
  set(html-docs)
  foreach(txt ${docs})
    string(REGEX REPLACE ".*/(.*)\\.txt" "\\1.html" html ${txt})
    set(src ${txt})
    set(dst doc/${html})
    if(WITH_DOC)
      add_custom_command(
        OUTPUT ${dst}
        COMMAND ${ASCIIDOC_EXECUTABLE} -d manpage -b xhtml11 -f ${CMAKE_CURRENT_SOURCE_DIR}/doc/asciidoc.conf
                -azmq_version=${ZMQ_VERSION} -o ${dst} ${src}
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${src}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating ${html}")
      list(APPEND html-docs ${CMAKE_CURRENT_BINARY_DIR}/${dst})
    endif()
  endforeach()
endif()

if(ZMQ_BUILD_FRAMEWORK)
  add_custom_command(
    TARGET libzmq
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} ARGS -E make_directory
            "${CMAKE_LIBRARY_OUTPUT_PATH}/ZeroMQ.framework/Versions/${ZMQ_VERSION}/MacOS"
    COMMENT "Perf tools")
endif()

option(ENABLE_PRECOMPILED "Enable precompiled headers, if possible" ON)
if(MSVC AND ENABLE_PRECOMPILED)
  # default for all sources is to use precompiled headers
  foreach(source ${sources})
    # C and C++ can not use the same precompiled header
    if(${source} MATCHES ".cpp$" AND NOT ${source} STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}/src/precompiled.cpp")
      set_source_files_properties(${source} PROPERTIES COMPILE_FLAGS "/Yuprecompiled.hpp" OBJECT_DEPENDS
                                                                                          precompiled.hpp)
    endif()
  endforeach()
  # create precompiled header
  set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/src/precompiled.cpp
                              PROPERTIES COMPILE_FLAGS "/Ycprecompiled.hpp" OBJECT_OUTPUTS precompiled.hpp)
endif()

# -----------------------------------------------------------------------------
# output
option(BUILD_SHARED "Whether or not to build the shared object" ON)
option(BUILD_STATIC "Whether or not to build the static archive" ON)

if(MSVC)
  # Suppress linker warnings caused by #ifdef omission of file content.
  set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /ignore:4221")
  set(PDB_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin")
  set(PDB_NAME
      "lib${ZMQ_OUTPUT_BASENAME}${MSVC_TOOLSET}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}")
  function(enable_vs_guideline_checker target)
    set_target_properties(
      ${target} PROPERTIES VS_GLOBAL_EnableCppCoreCheck true VS_GLOBAL_CodeAnalysisRuleSet CppCoreCheckRules.ruleset
                           VS_GLOBAL_RunCodeAnalysis true)
  endfunction()
  if(BUILD_SHARED)
    add_library(libzmq SHARED ${sources} ${public_headers} ${html-docs} ${readme-docs}
                              ${CMAKE_CURRENT_BINARY_DIR}/NSIS.template.in ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    if(ENABLE_ANALYSIS)
      enable_vs_guideline_checker(libzmq)
    endif()
    set_target_properties(
      libzmq
      PROPERTIES PUBLIC_HEADER "${public_headers}"
                 RELEASE_POSTFIX "${MSVC_TOOLSET}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 RELWITHDEBINFO_POSTFIX
                 "${MSVC_TOOLSET}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 MINSIZEREL_POSTFIX "${MSVC_TOOLSET}-mt-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 DEBUG_POSTFIX "${MSVC_TOOLSET}-mt-gd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
                 COMPILE_DEFINITIONS "DLL_EXPORT"
                 OUTPUT_NAME "lib${ZMQ_OUTPUT_BASENAME}")
    if(ZMQ_HAVE_WINDOWS_UWP)
      set_target_properties(libzmq PROPERTIES LINK_FLAGS_DEBUG "/OPT:NOICF /OPT:NOREF")
    endif()
  endif()

  if(BUILD_STATIC)
    add_library(libzmq-static STATIC ${sources} ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    set_target_properties(
      libzmq-static
      PROPERTIES PUBLIC_HEADER "${public_headers}"
                 RELEASE_POSTFIX "${MSVC_TOOLSET}-mt-s-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 RELWITHDEBINFO_POSTFIX
                 "${MSVC_TOOLSET}-mt-s-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 MINSIZEREL_POSTFIX
                 "${MSVC_TOOLSET}-mt-s-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 DEBUG_POSTFIX "${MSVC_TOOLSET}-mt-sgd-${ZMQ_VERSION_MAJOR}_${ZMQ_VERSION_MINOR}_${ZMQ_VERSION_PATCH}"
                 COMPILE_FLAGS "/DZMQ_STATIC"
                 OUTPUT_NAME "lib${ZMQ_OUTPUT_BASENAME}")
  endif()
else()
  # avoid building everything twice for shared + static only on *nix, as Windows needs different preprocessor defines in
  # static builds
  if(NOT MINGW)
    add_library(objects OBJECT ${sources})
    set_property(TARGET objects PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_include_directories(
      objects PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                     $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> $<INSTALL_INTERFACE:include>)
  endif()

  if(BUILD_SHARED)
    if(MINGW)
      add_library(libzmq SHARED ${sources} ${public_headers} ${html-docs} ${readme-docs} ${zmq-pkgconfig}
                                ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    else()
        if (CMAKE_GENERATOR STREQUAL "Xcode")
           add_library(libzmq SHARED ${sources} ${public_headers} ${html-docs} ${readme-docs}
                                     ${zmq-pkgconfig} ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
        else()
           add_library(libzmq SHARED $<TARGET_OBJECTS:objects> ${public_headers} ${html-docs} ${readme-docs}
                                     ${zmq-pkgconfig} ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
        endif()
     
    endif()
    # NOTE: the SOVERSION and VERSION MUST be the same as the one generated by libtool! It is NOT the same as the
    # version of the package.
    set_target_properties(
      libzmq PROPERTIES COMPILE_DEFINITIONS "DLL_EXPORT" PUBLIC_HEADER "${public_headers}" VERSION "5.2.5"
                        SOVERSION "5" OUTPUT_NAME "${ZMQ_OUTPUT_BASENAME}" PREFIX "lib")
    if(ZMQ_BUILD_FRAMEWORK)
      set_target_properties(
        libzmq
        PROPERTIES FRAMEWORK TRUE MACOSX_FRAMEWORK_IDENTIFIER "org.zeromq.libzmq" MACOSX_FRAMEWORK_SHORT_VERSION_STRING
                                                                                  ${ZMQ_VERSION}
                   MACOSX_FRAMEWORK_BUNDLE_VERSION ${ZMQ_VERSION})
      set_source_files_properties(${html-docs} PROPERTIES MACOSX_PACKAGE_LOCATION doc)
      set_source_files_properties(${readme-docs} PROPERTIES MACOSX_PACKAGE_LOCATION etc)
      set_source_files_properties(${zmq-pkgconfig} PROPERTIES MACOSX_PACKAGE_LOCATION lib/pkgconfig)
    endif()
  endif()

  if(BUILD_STATIC)
    if(MINGW)
      add_library(libzmq-static STATIC ${sources} ${public_headers} ${html-docs} ${readme-docs} ${zmq-pkgconfig}
                                       ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    else()
      if (CMAKE_GENERATOR STREQUAL "Xcode")
        add_library(libzmq-static STATIC ${sources} ${public_headers} ${html-docs} ${readme-docs}
                                         ${zmq-pkgconfig} ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
      else()
        add_library(libzmq-static STATIC $<TARGET_OBJECTS:objects> ${public_headers} ${html-docs} ${readme-docs}
                                         ${zmq-pkgconfig} ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
      endif()
    endif()
    if(CMAKE_SYSTEM_NAME MATCHES "QNX")
      target_link_libraries(libzmq-static m)
    endif()
    set_target_properties(
      libzmq-static PROPERTIES PUBLIC_HEADER "${public_headers}" OUTPUT_NAME "${ZMQ_OUTPUT_BASENAME}" PREFIX "lib")
  endif()
endif()

if(BUILD_STATIC)
  target_compile_definitions(libzmq-static PUBLIC ZMQ_STATIC)
endif()

list(APPEND target_outputs "")

if(BUILD_SHARED)
  list(APPEND target_outputs "libzmq")
endif()

if(BUILD_STATIC)
  list(APPEND target_outputs "libzmq-static")
endif()

foreach(target ${target_outputs})
  target_include_directories(
    ${target} PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                     $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> $<INSTALL_INTERFACE:include>)
endforeach()

if(BUILD_SHARED)
  target_link_libraries(libzmq ${CMAKE_THREAD_LIBS_INIT})
  if(GNUTLS_FOUND)
    target_link_libraries(libzmq ${GNUTLS_LIBRARIES})
  endif()

  if(NSS3_FOUND)
    target_link_libraries(libzmq ${NSS3_LIBRARIES})
  endif()

  if(LIBBSD_FOUND)
    target_link_libraries(libzmq ${LIBBSD_LIBRARIES})
  endif()

  if(SODIUM_FOUND)
    target_link_libraries(libzmq ${SODIUM_LIBRARIES})
    # On Solaris, libsodium depends on libssp
    if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
      target_link_libraries(libzmq ssp)
    endif()
  endif()

  if(HAVE_WS2_32)
    target_link_libraries(libzmq ws2_32)
  elseif(HAVE_WS2)
    target_link_libraries(libzmq ws2)
  endif()

  if(HAVE_RPCRT4)
    target_link_libraries(libzmq rpcrt4)
  endif()

  if(HAVE_IPHLAPI)
    target_link_libraries(libzmq iphlpapi)
  endif()

  if(RT_LIBRARY)
    target_link_libraries(libzmq -lrt)
  endif()

  if(norm_FOUND)
      target_link_libraries(libzmq norm::norm)
  endif()
endif()

if(BUILD_STATIC)
  target_link_libraries(libzmq-static ${CMAKE_THREAD_LIBS_INIT})
  if(GNUTLS_FOUND)
    target_link_libraries(libzmq-static ${GNUTLS_LIBRARIES})
  endif()

  if(LIBBSD_FOUND)
    target_link_libraries(libzmq-static ${LIBBSD_LIBRARIES})
  endif()

  if(NSS3_FOUND)
    target_link_libraries(libzmq-static ${NSS3_LIBRARIES})
  endif()

  if(SODIUM_FOUND)
    target_link_libraries(libzmq-static ${SODIUM_LIBRARIES})
    # On Solaris, libsodium depends on libssp
    if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
      target_link_libraries(libzmq-static ssp)
    endif()
  endif()

  if(HAVE_WS2_32)
    target_link_libraries(libzmq-static ws2_32)
  elseif(HAVE_WS2)
    target_link_libraries(libzmq-static ws2)
  endif()

  if(HAVE_RPCRT4)
    target_link_libraries(libzmq-static rpcrt4)
  endif()

  if(HAVE_IPHLAPI)
    target_link_libraries(libzmq-static iphlpapi)
  endif()

  if(RT_LIBRARY)
    target_link_libraries(libzmq-static -lrt)
  endif()

  if(CMAKE_SYSTEM_NAME MATCHES "QNX")
    add_definitions(-DUNITY_EXCLUDE_MATH_H)
  endif()

  if(norm_FOUND)
      target_link_libraries(libzmq-static norm::norm)
  endif()
endif()

if(BUILD_SHARED)
  set(perf-tools
      local_lat
      remote_lat
      local_thr
      remote_thr
      inproc_lat
      inproc_thr
      proxy_thr)

  if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug") # Why?
    option(WITH_PERF_TOOL "Build with perf-tools" ON)
  else()
    option(WITH_PERF_TOOL "Build with perf-tools" OFF)
  endif()

  if(WITH_PERF_TOOL)
    foreach(perf-tool ${perf-tools})
      add_executable(${perf-tool} perf/${perf-tool}.cpp)
      target_link_libraries(${perf-tool} libzmq)

      if(GNUTLS_FOUND)
        target_link_libraries(${perf-tool} ${GNUTLS_LIBRARIES})
      endif()

      if(LIBBSD_FOUND)
        target_link_libraries(${perf-tool} ${LIBBSD_LIBRARIES})
      endif()

      if(NSS3_FOUND)
        target_link_libraries(${perf-tool} ${NSS3_LIBRARIES})
      endif()

      if(SODIUM_FOUND)
        target_link_libraries(${perf-tool} ${SODIUM_LIBRARIES})
      endif()

      if(ZMQ_BUILD_FRAMEWORK)
        # Copy perf-tools binaries into Framework
        add_custom_command(
          TARGET libzmq
          ${perf-tool} POST_BUILD
          COMMAND ${CMAKE_COMMAND} ARGS -E copy "$<TARGET_FILE:${perf-tool}>"
                  "${LIBRARY_OUTPUT_PATH}/ZeroMQ.framework/Versions/${ZMQ_VERSION_STRING}/MacOS/${perf-tool}"
          VERBATIM
          COMMENT "Perf tools")
      else()
        install(TARGETS ${perf-tool} RUNTIME DESTINATION bin COMPONENT PerfTools)
      endif()
      if(ZMQ_HAVE_WINDOWS_UWP)
        set_target_properties(${perf-tool} PROPERTIES LINK_FLAGS_DEBUG "/OPT:NOICF /OPT:NOREF")
      endif()
    endforeach()

    if(BUILD_STATIC)
      add_executable(benchmark_radix_tree perf/benchmark_radix_tree.cpp)
      target_link_libraries(benchmark_radix_tree libzmq-static)
      target_include_directories(benchmark_radix_tree PUBLIC "${CMAKE_CURRENT_LIST_DIR}/src")
      if(ZMQ_HAVE_WINDOWS_UWP)
        set_target_properties(benchmark_radix_tree PROPERTIES LINK_FLAGS_DEBUG "/OPT:NOICF /OPT:NOREF")
      endif()
    endif()
  elseif(WITH_PERF_TOOL)
    message(FATAL_ERROR "Shared library disabled - perf-tools unavailable.")
  endif()
endif()

# -----------------------------------------------------------------------------
# tests

option(BUILD_TESTS "Whether or not to build the tests" ON)

set(ZMQ_BUILD_TESTS
    ${BUILD_TESTS}
    CACHE BOOL "Build the tests for ZeroMQ")

if(ZMQ_BUILD_TESTS)
  enable_testing() # Enable testing only works in root scope
  add_subdirectory(tests)
  if(BUILD_STATIC)
    add_subdirectory(unittests)
  else()
    message(WARNING "Not building unit tests, since BUILD_STATIC is not enabled")
  endif()
endif()

# -----------------------------------------------------------------------------
# installer

if(MSVC AND (BUILD_SHARED OR BUILD_STATIC))
  install(
    TARGETS ${target_outputs}
    EXPORT ${PROJECT_NAME}-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT SDK)
  if(MSVC_IDE)
    install(
      FILES ${PDB_OUTPUT_DIRECTORY}/\${CMAKE_INSTALL_CONFIG_NAME}/${PDB_NAME}.pdb
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      COMPONENT SDK
      OPTIONAL)
  else()
    install(
      FILES ${PDB_OUTPUT_DIRECTORY}/${PDB_NAME}.pdb
      DESTINATION ${CMAKE_INSTALL_BINDIR}
      COMPONENT SDK
      OPTIONAL)
  endif()
  if(BUILD_SHARED)
    install(
      TARGETS libzmq
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
      PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT Runtime)
  endif()
elseif(BUILD_SHARED OR BUILD_STATIC)
  install(
    TARGETS ${target_outputs}
    EXPORT ${PROJECT_NAME}-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FRAMEWORK DESTINATION "Library/Frameworks"
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

foreach(readme ${readme-docs})
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/${readme} ${CMAKE_CURRENT_BINARY_DIR}/${readme}.txt)

  if(NOT ZMQ_BUILD_FRAMEWORK)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${readme}.txt DESTINATION share/zmq)
  endif()
endforeach()

if(WITH_DOC)
  if(NOT ZMQ_BUILD_FRAMEWORK)
    install(
      FILES ${html-docs}
      DESTINATION doc/zmq
      COMPONENT RefGuide)
  endif()
endif()

if(WIN32)
  set(ZEROMQ_CMAKECONFIG_INSTALL_DIR
      "CMake"
      CACHE STRING "install path for ZeroMQConfig.cmake")
else()
  # CMake search path wants either "share" (AKA GNUInstallDirs DATAROOTDIR) for arch-independent, or LIBDIR for arch-
  # dependent, plus "cmake" as prefix
  set(ZEROMQ_CMAKECONFIG_INSTALL_DIR
      "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
      CACHE STRING "install path for ZeroMQConfig.cmake")
endif()

if((NOT CMAKE_VERSION VERSION_LESS 3.0) AND (BUILD_SHARED OR BUILD_STATIC))
  export(EXPORT ${PROJECT_NAME}-targets FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake")
endif()
configure_package_config_file(
  builds/cmake/${PROJECT_NAME}Config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
  INSTALL_DESTINATION ${ZEROMQ_CMAKECONFIG_INSTALL_DIR})
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
  VERSION ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}
  COMPATIBILITY AnyNewerVersion)
if(BUILD_SHARED OR BUILD_STATIC)
  install(
    EXPORT ${PROJECT_NAME}-targets
    FILE ${PROJECT_NAME}Targets.cmake
    DESTINATION ${ZEROMQ_CMAKECONFIG_INSTALL_DIR})
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
          DESTINATION ${ZEROMQ_CMAKECONFIG_INSTALL_DIR})
endif()

option(ENABLE_CPACK "Enables cpack rules" ON)
if(MSVC AND ENABLE_CPACK)
  if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    set(CMAKE_INSTALL_DEBUG_LIBRARIES_ONLY TRUE)
    set(CMAKE_INSTALL_DEBUG_LIBRARIES TRUE)
    set(CMAKE_INSTALL_UCRT_LIBRARIES TRUE)
  endif()
  include(InstallRequiredSystemLibraries)

  if(CMAKE_CL_64)
    set(arch_name "x64")
  else()
    set(arch_name "x86")
  endif()

  set(CPACK_NSIS_DISPLAY_NAME "ZeroMQ ${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}(${arch_name})")
  set(CPACK_PACKAGE_FILE_NAME "ZeroMQ-${ZMQ_VERSION_MAJOR}.${ZMQ_VERSION_MINOR}.${ZMQ_VERSION_PATCH}-${arch_name}")

  # TODO: I think this part was intended to be used when running cpack separately from cmake but I don't know how that
  # works.
  #
  # macro(add_crt_version version) set(rel_dir
  # "${CMAKE_CURRENT_BINARY_DIR}/build/${arch_name}/${version};ZeroMQ;ALL;/")
  # set(debug_dir
  # "${CMAKE_CURRENT_BINARY_DIR}/debug/${arch_name}/${version};ZeroMQ;ALL;/")
  # if(EXISTS ${rel_dir}) list(APPEND CPACK_INSTALL_CMAKE_PROJECTS ${rel_dir}) endif()

  # if(EXISTS ${debug_dir}) list(APPEND CPACK_INSTALL_CMAKE_PROJECTS ${rel_dir}) endmacro() endmacro()

  # add_crt_version(v110) add_crt_version(v100) add_crt_version(v90)

  list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})
  set(CPACK_GENERATOR "NSIS")
  set(CPACK_PACKAGE_NAME "ZeroMQ")
  set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "ZeroMQ lightweight messaging kernel")
  set(CPACK_PACKAGE_VENDOR "Miru")
  set(CPACK_NSIS_CONTACT "Steven McCoy <Steven.McCoy@miru.hk>")
  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_BINARY_DIR}\\\\COPYING.txt")
  # set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_BINARY_DIR}\\\\README.txt") set(CPACK_RESOURCE_FILE_WELCOME
  # "${CMAKE_CURRENT_BINARY_DIR}\\\\WELCOME.txt") There is a bug in NSI that does not handle full unix paths properly.
  # Make sure there is at least one set of four(4) backslashes.
  set(CPACK_NSIS_MUI_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\installer.ico")
  set(CPACK_NSIS_MUI_UNIICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\installer.ico")

  set(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}\\\\branding.bmp")
  set(CPACK_NSIS_COMPRESSOR "/SOLID lzma")
  set(CPACK_PACKAGE_VERSION ${ZMQ_VERSION})
  set(CPACK_PACKAGE_VERSION_MAJOR ${ZMQ_VERSION_MAJOR})
  set(CPACK_PACKAGE_VERSION_MINOR ${ZMQ_VERSION_MINOR})
  set(CPACK_PACKAGE_VERSION_PATCH ${ZMQ_VERSION_PATCH})
  # set(CPACK_PACKAGE_INSTALL_DIRECTORY "ZMQ Install Directory") set(CPACK_TEMPORARY_DIRECTORY "ZMQ Temporary CPack
  # Directory")

  include(CPack)

  cpack_add_component_group(Development DISPLAY_NAME "ZeroMQ software development kit" EXPANDED)
  cpack_add_component(PerfTools DISPLAY_NAME "ZeroMQ performance tools" INSTALL_TYPES FullInstall DevInstall)
  cpack_add_component(SourceCode DISPLAY_NAME "ZeroMQ source code" DISABLED INSTALL_TYPES FullInstall)
  cpack_add_component(
    SDK
    DISPLAY_NAME
    "ZeroMQ headers and libraries"
    INSTALL_TYPES
    FullInstall
    DevInstall
    GROUP
    Development)
  if(WITH_DOC)
    cpack_add_component(
      RefGuide
      DISPLAY_NAME
      "ZeroMQ reference guide"
      INSTALL_TYPES
      FullInstall
      DevInstall
      GROUP
      Development)
  endif()
  cpack_add_component(
    Runtime
    DISPLAY_NAME
    "ZeroMQ runtime files"
    REQUIRED
    INSTALL_TYPES
    FullInstall
    DevInstall
    MinInstall)
  cpack_add_install_type(FullInstall DISPLAY_NAME "Full install, including source code")
  cpack_add_install_type(DevInstall DISPLAY_NAME "Developer install, headers and libraries")
  cpack_add_install_type(MinInstall DISPLAY_NAME "Minimal install, runtime only")
endif()

# Export this for library to help build this as a sub-project
set(ZEROMQ_LIBRARY
    libzmq
    CACHE STRING "ZeroMQ library")

# Workaround for MSVS10 to avoid the Dialog Hell FIXME: This could be removed with future version of CMake.
if(MSVC_VERSION EQUAL 1600)
  set(ZMQ_SLN_FILENAME "${CMAKE_CURRENT_BINARY_DIR}/ZeroMQ.sln")
  if(EXISTS "${ZMQ_SLN_FILENAME}")
    file(APPEND "${ZMQ_SLN_FILENAME}" "\n# This should be regenerated!\n")
  endif()
endif()

# this cannot be moved, as it does not only contain function/macro definitions
option(ENABLE_CLANG "Include Clang" ON)
if (ENABLE_CLANG)
  include(ClangFormat)
endif()

# fixes https://github.com/zeromq/libzmq/issues/3776 The problem is, both libzmq-static libzmq try to use/generate
# precompiled.pch at the same time Add a dependency, so they run in order and so they dont get in each others way TODO
# still generates warning "build\x64-Debug\ninja : warning : multiple rules generate precompiled.hpp. builds involving
# this target will not be correct; continuing anyway [-w dupbuild=warn]"
if(MSVC
   AND ENABLE_PRECOMPILED
   AND BUILD_SHARED
   AND BUILD_STATIC)
  add_dependencies(libzmq-static libzmq)
endif()
