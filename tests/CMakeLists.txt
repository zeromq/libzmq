# CMake build script for ZeroMQ tests
cmake_minimum_required(VERSION "2.8.1")

# On Windows: solution file will be called tests.sln
project(tests)

set(tests
  test_ancillaries
  test_system
  test_pair_inproc
  test_pair_tcp
  test_reqrep_inproc
  test_reqrep_tcp
  test_hwm
  test_hwm_pubsub
  test_reqrep_device
  test_sub_forward
  test_invalid_rep
  test_msg_flags
  test_msg_ffn
  test_connect_resolve
  test_immediate
  test_last_endpoint
  test_term_endpoint
  test_router_mandatory
  test_probe_router
  test_stream
  test_stream_empty
  test_stream_disconnect
  test_disconnect_inproc
  test_unbind_wildcard
  test_ctx_options
  test_ctx_destroy
  test_security_no_zap_handler
  test_security_null
  test_security_plain
  test_security_zap
  test_iov
  test_spec_req
  test_spec_rep
  test_spec_dealer
  test_spec_router
  test_spec_pushpull
  test_req_correlate
  test_req_relaxed
  test_conflate
  test_inproc_connect
  test_issue_566
  test_shutdown_stress
  test_timeo
  test_many_sockets
  test_diffserv
  test_connect_rid
  test_xpub_nodrop
  test_pub_invert_matching
  test_setsockopt
  test_sockopt_hwm
  test_heartbeats
  test_atomics
  test_bind_src_address
  test_capabilities
  test_metadata
  test_router_handover
  test_srcfd
  test_stream_timeout
  test_xpub_manual
  test_xpub_welcome_msg
  test_xpub_verbose
  test_base85
  test_bind_after_connect_tcp
  test_sodium
  test_monitor
  test_socket_null
  test_reconnect_ivl
  test_mock_pub_sub
)

if(NOT WIN32)
  list(APPEND tests
    test_security_gssapi)
endif()

if(ZMQ_HAVE_CURVE)
  list(APPEND tests
    test_security_curve)
endif()

find_program(CAPSH_PROGRAM NAMES capsh)

if (CAPSH_PROGRAM)
    list(APPEND tests
        test_pair_tcp_cap_net_admin
        )
else()
    message(STATUS "capsh not found, skipping tests that require CAP_NET_ADMIN")
endif()

if(NOT WIN32)
  list(APPEND tests
    test_ipc_wildcard
    test_pair_ipc
    test_rebind_ipc
    test_reqrep_ipc
    test_proxy
    test_proxy_hwm
    test_proxy_single_socket
    test_proxy_terminate
    test_getsockopt_memset
    test_filter_ipc
    test_stream_exceeds_buffer
    test_router_mandatory_hwm
    test_use_fd
    test_zmq_poll_fd
  )
  if(HAVE_FORK)
    list(APPEND tests test_fork)
  endif()
  if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(APPEND tests
      test_abstract_ipc
      )
    if(ZMQ_HAVE_TIPC)
      list(APPEND tests
        test_address_tipc
        test_pair_tipc
        test_reqrep_device_tipc
        test_reqrep_tipc
        test_router_mandatory_tipc
        test_sub_forward_tipc
        test_connect_delay_tipc
        test_shutdown_stress_tipc
        test_term_endpoint_tipc
      )
    endif()
  endif()
endif()

if(WITH_VMCI)
  list(APPEND tests
    test_pair_vmci
    test_reqrep_vmci
  )
endif()

if(ENABLE_DRAFTS)
  list(APPEND tests
    test_poller
    test_thread_safe
    test_client_server
    test_timers
    test_radio_dish
    test_scatter_gather
    test_dgram
    test_app_meta
    test_router_notify
    test_xpub_manual_last_value
  )
endif()

# add location of platform.hpp for Windows builds
if(WIN32)
  add_definitions(-DZMQ_CUSTOM_PLATFORM_HPP)
  add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
  # Same name on 64bit systems
  link_libraries(ws2_32.lib)
endif()

add_library(unity STATIC
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.c"
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.h"
  "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity_internals.h")
set_target_properties(unity PROPERTIES
  PUBLIC_HEADER "${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.h")
target_compile_definitions(unity PUBLIC "UNITY_USE_COMMAND_LINE_ARGS" "UNITY_EXCLUDE_FLOAT")
target_include_directories(unity PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../external/unity")

set(TESTUTIL_SOURCES
    testutil.cpp
    testutil.hpp
    testutil_monitoring.cpp
    testutil_monitoring.hpp
    testutil_security.cpp
    testutil_security.hpp
    testutil_unity.cpp
    testutil_unity.hpp
    )
if(BUILD_STATIC)
    add_library(testutil-static STATIC ${TESTUTIL_SOURCES})
    target_link_libraries(testutil-static libzmq-static ${OPTIONAL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} unity)
endif()
if(BUILD_SHARED)
    add_library(testutil STATIC ${TESTUTIL_SOURCES})
    target_link_libraries(testutil libzmq ${OPTIONAL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} unity)
endif()
if(BUILD_STATIC AND NOT BUILD_SHARED)
    # use testutil-static for both tests and unit tests
    set(TESTUTIL_LIB testutil-static)
else()
    # use testutil for tests and testutil-static for unit tests
    set(TESTUTIL_LIB testutil)
endif()

if(MSVC_VERSION LESS 1700)
  set_source_files_properties("${CMAKE_CURRENT_LIST_DIR}/../external/unity/unity.c" PROPERTIES LANGUAGE CXX)
endif()

if(MSVC_VERSION LESS 1600)
  target_compile_definitions(unity PUBLIC "UNITY_EXCLUDE_STDINT_H")
endif()

# add include dirs for all targets
include_directories("${ZeroMQ_SOURCE_DIR}/../include" "${ZeroMQ_BINARY_DIR}")
if(WIN32)
  add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
endif()

foreach(test ${tests})
  # target_sources not supported before CMake 3.1
  if(ZMQ_HAVE_CURVE AND ${test} MATCHES test_security_curve)
    add_executable(${test} ${test}.cpp
      "../src/tweetnacl.c"
      "../src/err.cpp"
      "../src/random.cpp"
      "../src/clock.cpp")
  else()
    add_executable(${test} ${test}.cpp)
  endif()
  target_link_libraries(${test} ${TESTUTIL_LIB})
  if(WIN32)
    # This is the output for Debug dynamic builds on Visual Studio 6.0
    # You should provide the correct directory, don't know how to do it automatically
    find_path(LIBZMQ_PATH "libzmq.lib" PATHS "../bin/Win32/Debug/v120/dynamic")
    if(NOT ${LIBZMQ_PATH} STREQUAL "LIBZMQ_PATH-NOTFOUND")
      set_target_properties(${test} PROPERTIES LINK_FLAGS "/LIBPATH:${LIBZMQ_PATH}")
    endif()
  else()
    # per-test directories not generated on OS X / Darwin
    if(NOT ${CMAKE_CXX_COMPILER_ID} MATCHES "Clang.*")
      link_directories(${test} PRIVATE "${ZeroMQ_SOURCE_DIR}/../lib")
    endif()
  endif()
  
  if(RT_LIBRARY)
    target_link_libraries(${test} ${RT_LIBRARY})
  endif()

  if(CMAKE_SYSTEM_NAME MATCHES "QNX")
    target_link_libraries(${test} socket)
    target_link_libraries(${test} m)
  endif()

  if(WIN32)
    add_test(NAME ${test} WORKING_DIRECTORY ${LIBRARY_OUTPUT_PATH} COMMAND ${test})
  else()
    if (${test} MATCHES "_cap_net_admin")
      add_test(NAME ${test} COMMAND sh -c "sudo ${CAPSH_PROGRAM} --caps=cap_net_admin+eip -- -c $<TARGET_FILE:${test}>")
    else()
      add_test(NAME ${test} COMMAND ${test})
    endif()
  endif()
  set_tests_properties(${test} PROPERTIES TIMEOUT 10)
  set_tests_properties(${test} PROPERTIES SKIP_RETURN_CODE 77)
endforeach()

#override timeout for these tests
if(ZMQ_HAVE_CURVE)
  set_tests_properties(test_security_curve PROPERTIES TIMEOUT 60)
endif()
set_tests_properties(test_heartbeats PROPERTIES TIMEOUT 60)

if(WIN32 AND ${POLLER} MATCHES "epoll")
  set_tests_properties(test_many_sockets PROPERTIES TIMEOUT 120)
endif()

if(WIN32 AND ENABLE_DRAFTS)
  set_tests_properties(test_radio_dish PROPERTIES TIMEOUT 30)
endif()

#add additional required flags
#ZMQ_USE_TWEETNACL will already be defined when not using sodium
if(ZMQ_HAVE_CURVE AND NOT ZMQ_USE_TWEETNACL)
  target_compile_definitions(test_security_curve PRIVATE "-DZMQ_USE_TWEETNACL")
endif()

set_tests_properties(test_security_zap PROPERTIES TIMEOUT 60)

#Check whether all tests in the current folder are present
file(READ "${CMAKE_CURRENT_LIST_FILE}" CURRENT_LIST_FILE_CONTENT)
file(GLOB ALL_TEST_SOURCES "test_*.cpp")
foreach(TEST_SOURCE ${ALL_TEST_SOURCES})
  get_filename_component(TESTNAME "${TEST_SOURCE}" NAME_WE)
  string(REGEX MATCH "${TESTNAME}" MATCH_TESTNAME "${CURRENT_LIST_FILE_CONTENT}")
  if(NOT MATCH_TESTNAME)
    message(AUTHOR_WARNING "Test '${TESTNAME}' is not known to CTest.")
  endif()
endforeach()
