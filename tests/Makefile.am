INCLUDES = -I$(top_builddir)/include \
           -I$(top_srcdir)/include

LDADD = $(top_builddir)/src/libzmq.la

noinst_PROGRAMS = test_system \
                  test_pair_inproc \
                  test_pair_tcp \
                  test_reqrep_inproc \
                  test_reqrep_tcp \
                  test_hwm \
                  test_reqrep_device \
                  test_sub_forward \
                  test_invalid_rep \
                  test_msg_flags \
                  test_connect_resolve \
                  test_immediate \
                  test_last_endpoint \
                  test_term_endpoint \
                  test_monitor \
                  test_router_mandatory \
                  test_router_raw_empty \
                  test_probe_router \
                  test_stream \
                  test_disconnect_inproc \
                  test_ctx_options \
                  test_ctx_destroy \
                  test_security_null \
                  test_security_plain \
                  test_security_curve \
                  test_iov \
                  test_spec_req \
                  test_spec_rep \
                  test_spec_dealer \
                  test_spec_router \
                  test_spec_pushpull \
                  test_req_correlate \
                  test_req_relaxed \
                  test_conflate \
                  test_inproc_connect \
                  test_issue_566 \
                  test_abstract_ipc \
                  test_many_sockets

if !ON_MINGW
noinst_PROGRAMS += test_shutdown_stress \
                   test_pair_ipc \
                   test_reqrep_ipc \
                   test_timeo \
                   test_fork
endif

test_system_SOURCES = test_system.cpp
test_pair_inproc_SOURCES = test_pair_inproc.cpp testutil.hpp
test_pair_tcp_SOURCES = test_pair_tcp.cpp testutil.hpp
test_reqrep_inproc_SOURCES = test_reqrep_inproc.cpp testutil.hpp
test_reqrep_tcp_SOURCES = test_reqrep_tcp.cpp testutil.hpp
test_hwm_SOURCES = test_hwm.cpp
test_reqrep_device_SOURCES = test_reqrep_device.cpp
test_sub_forward_SOURCES = test_sub_forward.cpp
test_invalid_rep_SOURCES = test_invalid_rep.cpp
test_msg_flags_SOURCES = test_msg_flags.cpp
test_connect_resolve_SOURCES = test_connect_resolve.cpp
test_immediate_SOURCES = test_immediate.cpp
test_last_endpoint_SOURCES = test_last_endpoint.cpp
test_term_endpoint_SOURCES = test_term_endpoint.cpp
test_monitor_SOURCES = test_monitor.cpp
test_router_mandatory_SOURCES = test_router_mandatory.cpp
test_router_raw_empty_SOURCES = test_router_raw_empty.cpp
test_probe_router_SOURCES = test_probe_router.cpp
test_stream_SOURCES = test_stream.cpp
test_disconnect_inproc_SOURCES = test_disconnect_inproc.cpp
test_ctx_options_SOURCES = test_ctx_options.cpp
test_iov_SOURCES = test_iov.cpp
test_ctx_destroy_SOURCES = test_ctx_destroy.cpp
test_security_null_SOURCES = test_security_null.cpp
test_security_plain_SOURCES = test_security_plain.cpp
test_security_curve_SOURCES = test_security_curve.cpp
test_spec_req_SOURCES = test_spec_req.cpp
test_spec_rep_SOURCES = test_spec_rep.cpp
test_spec_dealer_SOURCES = test_spec_dealer.cpp
test_spec_router_SOURCES = test_spec_router.cpp
test_spec_pushpull_SOURCES = test_spec_pushpull.cpp
test_req_correlate_SOURCES = test_req_correlate.cpp
test_req_relaxed_SOURCES = test_req_relaxed.cpp
test_conflate_SOURCES = test_conflate.cpp
test_inproc_connect_SOURCES = test_inproc_connect.cpp
test_issue_566_SOURCES = test_issue_566.cpp
test_abstract_ipc_SOURCES = test_abstract_ipc.cpp
test_many_sockets_SOURCES = test_many_sockets.cpp
if !ON_MINGW
test_shutdown_stress_SOURCES = test_shutdown_stress.cpp
test_pair_ipc_SOURCES = test_pair_ipc.cpp testutil.hpp
test_reqrep_ipc_SOURCES = test_reqrep_ipc.cpp testutil.hpp
test_timeo_SOURCES = test_timeo.cpp
test_fork_SOURCES = test_fork.cpp
endif

#  Run the test cases
TESTS = $(noinst_PROGRAMS)

if !ON_LINUX
XFAIL_TESTS = test_abstract_ipc
endif
