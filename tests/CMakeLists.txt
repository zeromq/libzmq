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
)
if(NOT WIN32)
  list(APPEND tests
          test_monitor
          test_pair_ipc
          test_reqrep_ipc
          test_abstract_ipc
          test_proxy
          test_filter_ipc
  )
  if(HAVE_FORK)
    list(APPEND tests test_fork)
  endif()
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
endforeach()

if(NOT WIN32)
  if(NOT CMAKE_SYSTEM_NAME MATCHES "Linux")
    set_tests_properties(test_abstract_ipc PROPERTIES WILL_FAIL true)
  endif()
endif()

