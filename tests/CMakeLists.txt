# CMake build script for ZeroMQ tests

set(tests
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
        test_thread_safe
        test_client_server
        test_setsockopt
        test_sockopt_hwm
        test_heartbeats
        test_poller
        test_atomics
        test_bind_src_address
        test_capabilities
        test_ipc_wildcard
        test_metadata
        test_pair_tipc
        test_reqrep_device_tipc
        test_reqrep_tipc
        test_router_handover
        test_router_mandatory_tipc
        test_srcfd
        test_stream_timeout
        test_sub_forward_tipc
        test_xpub_manual
        test_xpub_welcome_msg
)
if(NOT WIN32)
  list(APPEND tests
          test_monitor
          test_pair_ipc
          test_reqrep_ipc
          test_abstract_ipc
          test_proxy
          test_proxy_single_socket
          test_proxy_terminate
          test_getsockopt_memset
          test_filter_ipc
          test_connect_delay_tipc
          test_shutdown_stress_tipc
          test_stream_exceeds_buffer
          test_router_mandatory_hwm
          test_term_endpoint_tipc
  )
  if(HAVE_FORK)
    list(APPEND tests test_fork)
  endif()
endif()

if(WITH_VMCI)
  list(APPEND tests
          test_pair_vmci
          test_reqrep_vmci
  )
endif()

foreach(test ${tests})
  add_executable(${test} ${test}.cpp)
  target_link_libraries(${test} libzmq)

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

if(NOT WIN32)
  if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    set_tests_properties(test_abstract_ipc PROPERTIES WILL_FAIL true)
  endif()
endif()

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
