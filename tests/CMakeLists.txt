# CMake build script for ZeroMQ tests
cmake_minimum_required(VERSION "2.8.1")

# On Windows: solution file will be called tests.sln
PROJECT(tests)

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
        test_unbind_inproc
        test_unbind_wildcard
        test_ctx_options
        test_ctx_destroy
        test_security_null
        test_security_plain
        test_security_curve
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
        test_base85
        test_bind_after_connect_tcp
        test_sodium
)
if(NOT WIN32)
  list(APPEND tests
          test_monitor
          test_ipc_wildcard
          test_pair_ipc
          test_reqrep_ipc
          test_proxy
          test_proxy_single_socket
          test_proxy_terminate
          test_getsockopt_memset
          test_filter_ipc
          test_stream_exceeds_buffer
          test_router_mandatory_hwm
          test_use_fd_ipc
          test_use_fd_tcp
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


IF (ENABLE_DRAFTS)
    list(APPEND tests
        test_poller
        test_thread_safe
        test_client_server
        test_timers
        test_radio_dish
        test_udp
        test_scatter_gather
        test_dgram
    )
ENDIF (ENABLE_DRAFTS)

# add location of platform.hpp for Windows builds
if(WIN32)
    add_definitions(-DZMQ_CUSTOM_PLATFORM_HPP)
    add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
    include_directories(../builds/msvc)
    # Same name on 64bit systems
    link_libraries(Ws2_32.lib)
endif()

# add library and include dirs for all targets
link_libraries(libzmq)
include_directories("${CMAKE_SOURCE_DIR}/../include")

foreach(test ${tests})
  add_executable(${test} ${test}.cpp)
  if(WIN32)
    # This is the output for Debug dynamic builds on Visual Studio 6.0
    # You should provide the correct directory, don't know how to do it automatically
    find_path(LIBZMQ_PATH "libzmq.lib" PATHS "../bin/Win32/Debug/v120/dynamic")
    if(NOT ${LIBZMQ_PATH} STREQUAL "LIBZMQ_PATH-NOTFOUND")
        SET_TARGET_PROPERTIES( ${test} PROPERTIES LINK_FLAGS "/LIBPATH:${LIBZMQ_PATH}" )
    endif()
  else()
    # per-test directories not generated on OS X / Darwin
    if (NOT ${CMAKE_CXX_COMPILER_ID} MATCHES "Clang.*")
        link_directories(${test} PRIVATE "${CMAKE_SOURCE_DIR}/../lib")
    endif()
  endif()

  if(RT_LIBRARY)
    target_link_libraries(${test} ${RT_LIBRARY} )
  endif()
  if(WIN32)
    add_test(NAME ${test} WORKING_DIRECTORY ${LIBRARY_OUTPUT_PATH} COMMAND ${test})
  else()
    add_test(NAME ${test} COMMAND ${test})
  endif()
  set_tests_properties(${test} PROPERTIES TIMEOUT 10)
endforeach()

#Check whether all tests in the current folder are present
file(READ "${CMAKE_CURRENT_LIST_FILE}" CURRENT_LIST_FILE_CONTENT)
file(GLOB ALL_TEST_SOURCES "test_*.cpp")
foreach(TEST_SOURCE ${ALL_TEST_SOURCES})
  get_filename_component(TESTNAME "${TEST_SOURCE}" NAME_WE)
  string(REGEX MATCH "${TESTNAME}" MATCH_TESTNAME "${CURRENT_LIST_FILE_CONTENT}")
  if (NOT MATCH_TESTNAME)
    message(AUTHOR_WARNING "Test '${TESTNAME}' is not known to CTest.")
  endif()
endforeach()
