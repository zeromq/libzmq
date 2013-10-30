INCLUDES = -I$(top_builddir)/include \
           -I$(top_srcdir)/include

LDADD = $(top_builddir)/src/libzmq.la

noinst_PROGRAMS = test_pair_inproc \
                  test_pair_tcp \
                  test_reqrep_inproc \
                  test_reqrep_tcp \
                  test_hwm \
                  test_reqrep_device \
                  test_sub_forward \
                  test_invalid_rep \
                  test_msg_flags \
                  test_connect_resolve \
                  test_connect_delay \
                  test_last_endpoint \
                  test_term_endpoint \
                  test_monitor \
                  test_router_mandatory \
                  test_disconnect_inproc


if !ON_MINGW
noinst_PROGRAMS += test_shutdown_stress \
                   test_pair_ipc \
                   test_reqrep_ipc \
                   test_timeo
endif

if ON_LINUX
noinst_PROGRAMS += test_connect_delay_tipc \
		   test_pair_tipc \
		   test_reqrep_device_tipc \
		   test_reqrep_tipc \
		   test_router_mandatory_tipc \
		   test_shutdown_stress_tipc \
		   test_sub_forward_tipc \
		   test_term_endpoint_tipc
endif

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
test_connect_delay_SOURCES = test_connect_delay.cpp
test_last_endpoint_SOURCES = test_last_endpoint.cpp
test_term_endpoint_SOURCES = test_term_endpoint.cpp
test_monitor_SOURCES = test_monitor.cpp
test_disconnect_inproc_SOURCES = test_disconnect_inproc.cpp
test_router_mandatory_SOURCES = test_router_mandatory.cpp

if ON_LINUX
test_connect_delay_tipc_SOURCES = test_connect_delay_tipc.cpp
test_pair_tipc_SOURCES = test_pair_tipc.cpp
test_reqrep_device_tipc_SOURCES = test_reqrep_device_tipc.cpp
test_reqrep_tipc_SOURCES = test_reqrep_tipc.cpp
test_router_mandatory_tipc_SOURCES = test_router_mandatory_tipc.cpp
test_shutdown_stress_tipc_SOURCES = test_shutdown_stress_tipc.cpp
test_sub_forward_tipc_SOURCES = test_sub_forward_tipc.cpp
test_term_endpoint_tipc_SOURCES = test_term_endpoint_tipc.cpp
endif

if !ON_MINGW
test_shutdown_stress_SOURCES = test_shutdown_stress.cpp
test_pair_ipc_SOURCES = test_pair_ipc.cpp testutil.hpp
test_reqrep_ipc_SOURCES = test_reqrep_ipc.cpp testutil.hpp
test_timeo_SOURCES = test_timeo.cpp
endif

TESTS = $(noinst_PROGRAMS)
