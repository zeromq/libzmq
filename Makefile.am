ACLOCAL_AMFLAGS = -I config

SUBDIRS = doc

DIST_SUBDIRS = doc builds builds/msvc

pkgconfig_DATA = src/libzmq.pc

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

#
# libraries/binaries
#
lib_LTLIBRARIES = src/libzmq.la

include_HEADERS = \
	include/zmq.h \
	include/zmq_utils.h

src_libzmq_la_SOURCES = \
	src/address.cpp \
	src/address.hpp \
	src/array.hpp \
	src/atomic_counter.hpp \
	src/atomic_ptr.hpp \
	src/blob.hpp \
	src/client.cpp \
	src/client.hpp \
	src/clock.cpp \
	src/clock.hpp \
	src/command.hpp \
	src/condition_variable.hpp \
	src/config.hpp \
	src/ctx.cpp \
	src/ctx.hpp \
	src/curve_client.cpp \
	src/curve_client.hpp \
	src/curve_server.cpp \
	src/curve_server.hpp \
	src/dbuffer.hpp \
	src/dealer.cpp \
	src/dealer.hpp \
	src/decoder.hpp \
	src/devpoll.cpp \
	src/devpoll.hpp \
	src/dgram.cpp \
	src/dgram.hpp \
	src/dish.cpp \
	src/dish.hpp \
	src/dist.cpp \
	src/dist.hpp \
	src/encoder.hpp \
	src/epoll.cpp \
	src/epoll.hpp \
	src/err.cpp \
	src/err.hpp \
	src/fd.hpp \
	src/fq.cpp \
	src/fq.hpp \
	src/gather.cpp \
	src/gather.hpp \
	src/gssapi_mechanism_base.cpp \
	src/gssapi_mechanism_base.hpp \
	src/gssapi_client.cpp \
	src/gssapi_client.hpp \
	src/gssapi_server.cpp \
	src/gssapi_server.hpp \
	src/i_encoder.hpp \
	src/i_engine.hpp \
	src/i_decoder.hpp \
	src/i_mailbox.hpp \
	src/i_poll_events.hpp \
	src/io_object.cpp \
	src/io_object.hpp \
	src/io_thread.cpp \
	src/io_thread.hpp \
	src/ip.cpp \
	src/ip.hpp \
	src/ipc_address.cpp \
	src/ipc_address.hpp \
	src/ipc_connecter.cpp \
	src/ipc_connecter.hpp \
	src/ipc_listener.cpp \
	src/ipc_listener.hpp \
	src/kqueue.cpp \
	src/kqueue.hpp \
	src/lb.cpp \
	src/lb.hpp \
	src/likely.hpp \
	src/macros.hpp \
	src/mailbox.cpp \
	src/mailbox.hpp \
	src/mailbox_safe.cpp \
	src/mailbox_safe.hpp \
	src/mechanism.cpp \
	src/mechanism.hpp  \
	src/metadata.cpp \
	src/metadata.hpp \
	src/msg.cpp \
	src/msg.hpp \
	src/mtrie.cpp \
	src/mtrie.hpp \
	src/mutex.hpp \
	src/norm_engine.cpp \
	src/norm_engine.hpp \
	src/null_mechanism.cpp \
	src/null_mechanism.hpp \
	src/object.cpp \
	src/object.hpp \
	src/options.cpp \
	src/options.hpp \
	src/own.cpp \
	src/own.hpp \
	src/pair.cpp \
	src/pair.hpp \
	src/pgm_receiver.cpp \
	src/pgm_receiver.hpp \
	src/pgm_sender.cpp \
	src/pgm_sender.hpp \
	src/pgm_socket.cpp \
	src/pgm_socket.hpp \
	src/pipe.cpp \
	src/pipe.hpp \
	src/plain_client.cpp \
	src/plain_client.hpp \
	src/plain_server.cpp \
	src/plain_server.hpp \
	src/platform.hpp \
	src/poll.cpp \
	src/poll.hpp \
	src/poller.hpp \
	src/poller_base.cpp \
	src/poller_base.hpp \
	src/pollset.cpp \
	src/pollset.hpp \
	src/precompiled.cpp \
	src/precompiled.hpp \
	src/proxy.cpp \
	src/proxy.hpp \
	src/pub.cpp \
	src/pub.hpp \
	src/pull.cpp \
	src/pull.hpp \
	src/push.cpp \
	src/push.hpp \
	src/radio.cpp \
	src/radio.hpp \
	src/random.cpp \
	src/random.hpp \
	src/raw_decoder.cpp \
	src/raw_decoder.hpp \
	src/raw_encoder.cpp \
	src/raw_encoder.hpp \
	src/reaper.cpp \
	src/reaper.hpp \
	src/rep.cpp \
	src/rep.hpp \
	src/req.cpp \
	src/req.hpp \
	src/router.cpp \
	src/router.hpp \
	src/scatter.cpp \
	src/scatter.hpp \
	src/select.cpp \
	src/select.hpp \
	src/server.cpp \
	src/server.hpp \
	src/session_base.cpp \
	src/session_base.hpp \
	src/signaler.cpp \
	src/signaler.hpp \
	src/socket_base.cpp \
	src/socket_base.hpp \
	src/socks.cpp \
	src/socks.hpp \
	src/socks_connecter.cpp \
	src/socks_connecter.hpp \
	src/stdint.hpp \
	src/stream.cpp \
	src/stream.hpp \
	src/stream_engine.cpp \
	src/stream_engine.hpp \
	src/sub.cpp \
	src/sub.hpp \
	src/tcp.cpp \
	src/tcp.hpp \
	src/tcp_address.cpp \
	src/tcp_address.hpp \
	src/tcp_connecter.cpp \
	src/tcp_connecter.hpp \
	src/tcp_listener.cpp \
	src/tcp_listener.hpp \
	src/thread.cpp \
	src/thread.hpp \
	src/timers.cpp \
	src/timers.hpp \
	src/tipc_address.cpp \
	src/tipc_address.hpp \
	src/tipc_connecter.cpp \
	src/tipc_connecter.hpp \
	src/tipc_listener.cpp \
	src/tipc_listener.hpp \
	src/trie.cpp \
	src/trie.hpp \
	src/udp_address.cpp \
	src/udp_address.hpp \
	src/udp_engine.cpp \
	src/udp_engine.hpp \
	src/v1_decoder.cpp \
	src/v1_decoder.hpp \
	src/v2_decoder.cpp \
	src/v2_decoder.hpp \
	src/v1_encoder.cpp \
	src/v1_encoder.hpp \
	src/v2_encoder.cpp \
	src/v2_encoder.hpp \
	src/v2_protocol.hpp \
	src/vmci.cpp \
	src/vmci.hpp \
	src/vmci_address.cpp \
	src/vmci_address.hpp \
	src/vmci_connecter.cpp \
	src/vmci_connecter.hpp \
	src/vmci_listener.cpp \
	src/vmci_listener.hpp \
	src/windows.hpp \
	src/wire.hpp \
	src/xpub.cpp \
	src/xpub.hpp \
	src/xsub.cpp \
	src/xsub.hpp \
	src/ypipe.hpp \
	src/ypipe_base.hpp \
	src/ypipe_conflate.hpp \
	src/yqueue.hpp \
	src/zmq.cpp \
	src/zmq_utils.cpp \
	src/decoder_allocators.cpp \
	src/decoder_allocators.hpp \
	src/socket_poller.cpp \
	src/socket_poller.hpp \
	src/zmq_draft.h

if USE_TWEETNACL
src_libzmq_la_SOURCES += \
	src/tweetnacl.c \
	src/tweetnacl.h
endif

if ON_MINGW
src_libzmq_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
else
if ON_CYGWIN
src_libzmq_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
else
if ON_ANDROID
src_libzmq_la_LDFLAGS = \
	-avoid-version \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
else
if ON_LINUX
src_libzmq_la_LDFLAGS = \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@ \
	-Wl,--version-script=$(srcdir)/src/libzmq.vers
else
src_libzmq_la_LDFLAGS = \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@ \
	-Wl
endif
endif
endif
endif

src_libzmq_la_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS) $(LIBUNWIND_CFLAGS)
src_libzmq_la_CFLAGS = $(CODE_COVERAGE_CFLAGS) $(LIBUNWIND_CFLAGS)
src_libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@ $(CODE_COVERAGE_CXXFLAGS) \
	$(LIBUNWIND_CFLAGS)
src_libzmq_la_LIBADD = $(CODE_COVERAGE_LDFLAGS) $(LIBUNWIND_LIBS)

if USE_LIBSODIUM
src_libzmq_la_CPPFLAGS += ${sodium_CFLAGS}
src_libzmq_la_LIBADD += ${sodium_LIBS}
endif

if HAVE_PGM
src_libzmq_la_CPPFLAGS += ${pgm_CFLAGS}
src_libzmq_la_LIBADD += ${pgm_LIBS}
endif

if ENABLE_PERF
noinst_PROGRAMS = \
	perf/local_lat \
	perf/remote_lat \
	perf/local_thr \
	perf/remote_thr \
	perf/inproc_lat \
	perf/inproc_thr

perf_local_lat_LDADD = src/libzmq.la
perf_local_lat_SOURCES = perf/local_lat.cpp

perf_remote_lat_LDADD = src/libzmq.la
perf_remote_lat_SOURCES = perf/remote_lat.cpp

perf_local_thr_LDADD = src/libzmq.la
perf_local_thr_SOURCES = perf/local_thr.cpp

perf_remote_thr_LDADD = src/libzmq.la
perf_remote_thr_SOURCES = perf/remote_thr.cpp

perf_inproc_lat_LDADD = src/libzmq.la
perf_inproc_lat_SOURCES = perf/inproc_lat.cpp

perf_inproc_thr_LDADD = src/libzmq.la
perf_inproc_thr_SOURCES = perf/inproc_thr.cpp
endif

if ENABLE_CURVE_KEYGEN
bin_PROGRAMS = tools/curve_keygen

tools_curve_keygen_LDADD = src/libzmq.la
tools_curve_keygen_SOURCES = tools/curve_keygen.cpp
endif

#
# tests
#
test_apps = \
	tests/test_ancillaries \
	tests/test_system \
	tests/test_pair_inproc \
	tests/test_pair_tcp \
	tests/test_reqrep_inproc \
	tests/test_reqrep_tcp \
	tests/test_hwm \
	tests/test_hwm_pubsub \
	tests/test_reqrep_device \
	tests/test_sub_forward \
	tests/test_invalid_rep \
	tests/test_msg_flags \
	tests/test_msg_ffn \
	tests/test_connect_resolve \
	tests/test_immediate \
	tests/test_last_endpoint \
	tests/test_term_endpoint \
	tests/test_srcfd \
	tests/test_monitor \
	tests/test_router_mandatory \
	tests/test_router_mandatory_hwm \
	tests/test_router_handover \
	tests/test_probe_router \
	tests/test_stream \
	tests/test_stream_empty \
	tests/test_stream_disconnect \
	tests/test_stream_timeout \
	tests/test_disconnect_inproc \
	tests/test_unbind_inproc \
	tests/test_unbind_wildcard \
	tests/test_ctx_options \
	tests/test_ctx_destroy \
	tests/test_security_null \
	tests/test_security_plain \
	tests/test_security_curve \
	tests/test_iov \
	tests/test_spec_req \
	tests/test_spec_rep \
	tests/test_spec_dealer \
	tests/test_spec_router \
	tests/test_spec_pushpull \
	tests/test_req_correlate \
	tests/test_req_relaxed \
	tests/test_conflate \
	tests/test_inproc_connect \
	tests/test_issue_566 \
	tests/test_proxy \
	tests/test_proxy_single_socket \
	tests/test_proxy_terminate \
	tests/test_getsockopt_memset \
	tests/test_setsockopt \
	tests/test_many_sockets \
	tests/test_diffserv \
	tests/test_connect_rid \
	tests/test_bind_src_address \
	tests/test_metadata \
	tests/test_capabilities \
	tests/test_xpub_nodrop \
	tests/test_xpub_manual \
	tests/test_xpub_welcome_msg \
	tests/test_atomics \
	tests/test_sockopt_hwm \
	tests/test_heartbeats \
	tests/test_stream_exceeds_buffer \
	tests/test_pub_invert_matching \
	tests/test_base85 \
	tests/test_bind_after_connect_tcp \
	tests/test_sodium

tests_test_ancillaries_SOURCES = tests/test_ancillaries.cpp
tests_test_ancillaries_LDADD = src/libzmq.la

tests_test_system_SOURCES = tests/test_system.cpp
tests_test_system_LDADD = src/libzmq.la

tests_test_pair_inproc_SOURCES = \
	tests/test_pair_inproc.cpp \
	tests/testutil.hpp
tests_test_pair_inproc_LDADD = src/libzmq.la

tests_test_pair_tcp_SOURCES = \
	tests/test_pair_tcp.cpp \
	tests/testutil.hpp
tests_test_pair_tcp_LDADD = src/libzmq.la

tests_test_reqrep_inproc_SOURCES = \
	tests/test_reqrep_inproc.cpp \
	tests/testutil.hpp
tests_test_reqrep_inproc_LDADD = src/libzmq.la

tests_test_reqrep_tcp_SOURCES = \
	tests/test_reqrep_tcp.cpp \
	tests/testutil.hpp
tests_test_reqrep_tcp_LDADD = src/libzmq.la

tests_test_hwm_SOURCES = tests/test_hwm.cpp
tests_test_hwm_LDADD = src/libzmq.la

tests_test_hwm_pubsub_SOURCES = tests/test_hwm_pubsub.cpp
tests_test_hwm_pubsub_LDADD = src/libzmq.la

tests_test_reqrep_device_SOURCES = tests/test_reqrep_device.cpp
tests_test_reqrep_device_LDADD = src/libzmq.la

tests_test_sub_forward_SOURCES = tests/test_sub_forward.cpp
tests_test_sub_forward_LDADD = src/libzmq.la

tests_test_invalid_rep_SOURCES = tests/test_invalid_rep.cpp
tests_test_invalid_rep_LDADD = src/libzmq.la

tests_test_msg_flags_SOURCES = tests/test_msg_flags.cpp
tests_test_msg_flags_LDADD = src/libzmq.la

tests_test_msg_ffn_SOURCES = tests/test_msg_ffn.cpp
tests_test_msg_ffn_LDADD = src/libzmq.la

tests_test_connect_resolve_SOURCES = tests/test_connect_resolve.cpp
tests_test_connect_resolve_LDADD = src/libzmq.la

tests_test_immediate_SOURCES = tests/test_immediate.cpp
tests_test_immediate_LDADD = src/libzmq.la

tests_test_last_endpoint_SOURCES = tests/test_last_endpoint.cpp
tests_test_last_endpoint_LDADD = src/libzmq.la

tests_test_term_endpoint_SOURCES = tests/test_term_endpoint.cpp
tests_test_term_endpoint_LDADD = src/libzmq.la

tests_test_srcfd_SOURCES = tests/test_srcfd.cpp
tests_test_srcfd_LDADD = src/libzmq.la

tests_test_monitor_SOURCES = tests/test_monitor.cpp
tests_test_monitor_LDADD = src/libzmq.la

tests_test_router_mandatory_SOURCES = tests/test_router_mandatory.cpp
tests_test_router_mandatory_LDADD = src/libzmq.la

tests_test_router_mandatory_hwm_SOURCES = tests/test_router_mandatory_hwm.cpp
tests_test_router_mandatory_hwm_LDADD = src/libzmq.la

tests_test_router_handover_SOURCES = tests/test_router_handover.cpp
tests_test_router_handover_LDADD = src/libzmq.la

tests_test_probe_router_SOURCES = tests/test_probe_router.cpp
tests_test_probe_router_LDADD = src/libzmq.la

tests_test_stream_SOURCES = tests/test_stream.cpp
tests_test_stream_LDADD = src/libzmq.la

tests_test_stream_empty_SOURCES = tests/test_stream_empty.cpp
tests_test_stream_empty_LDADD = src/libzmq.la

tests_test_stream_timeout_SOURCES = tests/test_stream_timeout.cpp
tests_test_stream_timeout_LDADD = src/libzmq.la

tests_test_stream_disconnect_SOURCES = tests/test_stream_disconnect.cpp
tests_test_stream_disconnect_LDADD = src/libzmq.la

tests_test_disconnect_inproc_SOURCES = tests/test_disconnect_inproc.cpp
tests_test_disconnect_inproc_LDADD = src/libzmq.la

tests_test_unbind_inproc_SOURCES = tests/test_unbind_inproc.cpp
tests_test_unbind_inproc_LDADD = src/libzmq.la

tests_test_unbind_wildcard_SOURCES = tests/test_unbind_wildcard.cpp
tests_test_unbind_wildcard_LDADD = src/libzmq.la

tests_test_ctx_options_SOURCES = tests/test_ctx_options.cpp
tests_test_ctx_options_LDADD = src/libzmq.la

tests_test_iov_SOURCES = tests/test_iov.cpp
tests_test_iov_LDADD = src/libzmq.la

tests_test_ctx_destroy_SOURCES = tests/test_ctx_destroy.cpp
tests_test_ctx_destroy_LDADD = src/libzmq.la

tests_test_security_null_SOURCES = tests/test_security_null.cpp
tests_test_security_null_LDADD = src/libzmq.la

tests_test_security_plain_SOURCES = tests/test_security_plain.cpp
tests_test_security_plain_LDADD = src/libzmq.la

tests_test_security_curve_SOURCES = tests/test_security_curve.cpp
tests_test_security_curve_LDADD = src/libzmq.la

tests_test_spec_req_SOURCES = tests/test_spec_req.cpp
tests_test_spec_req_LDADD = src/libzmq.la

tests_test_spec_rep_SOURCES = tests/test_spec_rep.cpp
tests_test_spec_rep_LDADD = src/libzmq.la

tests_test_spec_dealer_SOURCES = tests/test_spec_dealer.cpp
tests_test_spec_dealer_LDADD = src/libzmq.la

tests_test_spec_router_SOURCES = tests/test_spec_router.cpp
tests_test_spec_router_LDADD = src/libzmq.la

tests_test_spec_pushpull_SOURCES = tests/test_spec_pushpull.cpp
tests_test_spec_pushpull_LDADD = src/libzmq.la

tests_test_req_correlate_SOURCES = tests/test_req_correlate.cpp
tests_test_req_correlate_LDADD = src/libzmq.la

tests_test_req_relaxed_SOURCES = tests/test_req_relaxed.cpp
tests_test_req_relaxed_LDADD = src/libzmq.la

tests_test_conflate_SOURCES = tests/test_conflate.cpp
tests_test_conflate_LDADD = src/libzmq.la

tests_test_inproc_connect_SOURCES = tests/test_inproc_connect.cpp
tests_test_inproc_connect_LDADD = src/libzmq.la

tests_test_issue_566_SOURCES = tests/test_issue_566.cpp
tests_test_issue_566_LDADD = src/libzmq.la

tests_test_proxy_SOURCES = tests/test_proxy.cpp
tests_test_proxy_LDADD = src/libzmq.la

tests_test_proxy_single_socket_SOURCES = tests/test_proxy_single_socket.cpp
tests_test_proxy_single_socket_LDADD = src/libzmq.la

tests_test_proxy_terminate_SOURCES = tests/test_proxy_terminate.cpp
tests_test_proxy_terminate_LDADD = src/libzmq.la

tests_test_getsockopt_memset_SOURCES = tests/test_getsockopt_memset.cpp
tests_test_getsockopt_memset_LDADD = src/libzmq.la

tests_test_many_sockets_SOURCES = tests/test_many_sockets.cpp
tests_test_many_sockets_LDADD = src/libzmq.la

tests_test_diffserv_SOURCES = tests/test_diffserv.cpp
tests_test_diffserv_LDADD = src/libzmq.la

tests_test_connect_rid_SOURCES = tests/test_connect_rid.cpp
tests_test_connect_rid_LDADD = src/libzmq.la

tests_test_bind_src_address_SOURCES = tests/test_bind_src_address.cpp
tests_test_bind_src_address_LDADD = src/libzmq.la

tests_test_metadata_SOURCES = tests/test_metadata.cpp
tests_test_metadata_LDADD = src/libzmq.la

tests_test_capabilities_SOURCES = tests/test_capabilities.cpp
tests_test_capabilities_LDADD = src/libzmq.la

tests_test_xpub_nodrop_SOURCES = tests/test_xpub_nodrop.cpp
tests_test_xpub_nodrop_LDADD = src/libzmq.la

tests_test_xpub_manual_SOURCES = tests/test_xpub_manual.cpp
tests_test_xpub_manual_LDADD = src/libzmq.la

tests_test_xpub_welcome_msg_SOURCES = tests/test_xpub_welcome_msg.cpp
tests_test_xpub_welcome_msg_LDADD = src/libzmq.la

tests_test_atomics_SOURCES = tests/test_atomics.cpp
tests_test_atomics_LDADD = src/libzmq.la

tests_test_sockopt_hwm_SOURCES = tests/test_sockopt_hwm.cpp
tests_test_sockopt_hwm_LDADD = src/libzmq.la

tests_test_setsockopt_SOURCES = tests/test_setsockopt.cpp
tests_test_setsockopt_LDADD = src/libzmq.la

tests_test_heartbeats_SOURCES = tests/test_heartbeats.cpp
tests_test_heartbeats_LDADD = src/libzmq.la

tests_test_stream_exceeds_buffer_SOURCES = tests/test_stream_exceeds_buffer.cpp
tests_test_stream_exceeds_buffer_LDADD = src/libzmq.la

tests_test_pub_invert_matching_SOURCES = tests/test_pub_invert_matching.cpp
tests_test_pub_invert_matching_LDADD = src/libzmq.la

tests_test_bind_after_connect_tcp_SOURCES = tests/test_bind_after_connect_tcp.cpp
tests_test_bind_after_connect_tcp_LDADD = src/libzmq.la

tests_test_base85_SOURCES = tests/test_base85.cpp
tests_test_base85_LDADD = src/libzmq.la

tests_test_sodium_SOURCES = tests/test_sodium.cpp
tests_test_sodium_LDADD = src/libzmq.la

if !ON_MINGW
if !ON_CYGWIN
test_apps += \
	tests/test_shutdown_stress \
	tests/test_ipc_wildcard \
	tests/test_pair_ipc \
	tests/test_reqrep_ipc \
	tests/test_use_fd_ipc \
	tests/test_use_fd_tcp \
	tests/test_zmq_poll_fd \
	tests/test_timeo \
	tests/test_filter_ipc

tests_test_shutdown_stress_SOURCES = tests/test_shutdown_stress.cpp
tests_test_shutdown_stress_LDADD = src/libzmq.la

tests_test_ipc_wildcard_SOURCES = tests/test_ipc_wildcard.cpp
tests_test_ipc_wildcard_LDADD = src/libzmq.la

tests_test_pair_ipc_SOURCES = \
	tests/test_pair_ipc.cpp \
	tests/testutil.hpp
tests_test_pair_ipc_LDADD = src/libzmq.la

tests_test_reqrep_ipc_SOURCES = \
	tests/test_reqrep_ipc.cpp \
	tests/testutil.hpp
tests_test_reqrep_ipc_LDADD = src/libzmq.la

tests_test_timeo_SOURCES = tests/test_timeo.cpp
tests_test_timeo_LDADD = src/libzmq.la

tests_test_filter_ipc_SOURCES = tests/test_filter_ipc.cpp
tests_test_filter_ipc_LDADD = src/libzmq.la

tests_test_use_fd_ipc_SOURCES = \
	tests/test_use_fd_ipc.cpp \
	tests/testutil.hpp
tests_test_use_fd_ipc_LDADD = src/libzmq.la

tests_test_use_fd_tcp_SOURCES = \
	tests/test_use_fd_tcp.cpp \
	tests/testutil.hpp
tests_test_use_fd_tcp_LDADD = src/libzmq.la

tests_test_zmq_poll_fd_SOURCES = tests/test_zmq_poll_fd.cpp
tests_test_zmq_poll_fd_LDADD = src/libzmq.la

if HAVE_FORK
if !VALGRIND_ENABLED
test_apps += tests/test_fork

tests_test_fork_SOURCES = tests/test_fork.cpp
tests_test_fork_LDADD = src/libzmq.la

endif
endif
endif
endif

if BUILD_TIPC
test_apps += \
	tests/test_connect_delay_tipc \
	tests/test_pair_tipc \
	tests/test_reqrep_device_tipc \
	tests/test_reqrep_tipc \
	tests/test_router_mandatory_tipc \
	tests/test_shutdown_stress_tipc \
	tests/test_sub_forward_tipc \
	tests/test_term_endpoint_tipc

tests_test_connect_delay_tipc_SOURCES = tests/test_connect_delay_tipc.cpp
tests_test_connect_delay_tipc_LDADD = src/libzmq.la

tests_test_pair_tipc_SOURCES = tests/test_pair_tipc.cpp
tests_test_pair_tipc_LDADD = src/libzmq.la

tests_test_reqrep_device_tipc_SOURCES = tests/test_reqrep_device_tipc.cpp
tests_test_reqrep_device_tipc_LDADD = src/libzmq.la

tests_test_reqrep_tipc_SOURCES = tests/test_reqrep_tipc.cpp
tests_test_reqrep_tipc_LDADD = src/libzmq.la

tests_test_router_mandatory_tipc_SOURCES = tests/test_router_mandatory_tipc.cpp
tests_test_router_mandatory_tipc_LDADD = src/libzmq.la

tests_test_shutdown_stress_tipc_SOURCES = tests/test_shutdown_stress_tipc.cpp
tests_test_shutdown_stress_tipc_LDADD = src/libzmq.la

tests_test_sub_forward_tipc_SOURCES = tests/test_sub_forward_tipc.cpp
tests_test_sub_forward_tipc_LDADD = src/libzmq.la

tests_test_term_endpoint_tipc_SOURCES = tests/test_term_endpoint_tipc.cpp
tests_test_term_endpoint_tipc_LDADD = src/libzmq.la

endif

if ON_LINUX
test_apps += tests/test_abstract_ipc

tests_test_abstract_ipc_SOURCES = tests/test_abstract_ipc.cpp
tests_test_abstract_ipc_LDADD = src/libzmq.la

endif

if HAVE_VMCI
test_apps += test_pair_vmci test_reqrep_vmci

test_pair_vmci_SOURCES = tests/test_pair_vmci.cpp
test_pair_vmci_LDADD = libzmq.la
test_pair_vmci_LDFLAGS = @LIBZMQ_VMCI_LDFLAGS@
test_pair_vmci_CXXFLAGS = @LIBZMQ_VMCI_CXXFLAGS@

test_reqrep_vmci_SOURCES = tests/test_reqrep_vmci.cpp
test_reqrep_vmci_LDADD = libzmq.la
test_reqrep_vmci_LDFLAGS = @LIBZMQ_VMCI_LDFLAGS@
test_reqrep_vmci_CXXFLAGS = @LIBZMQ_VMCI_CXXFLAGS@

endif

if ENABLE_DRAFTS
test_apps += tests/test_poller \
	tests/test_client_server \
	tests/test_thread_safe \
	tests/test_timers \
	tests/test_radio_dish \
	tests/test_udp \
	tests/test_scatter_gather \
	tests/test_dgram

tests_test_poller_SOURCES = tests/test_poller.cpp
tests_test_poller_LDADD = src/libzmq.la

tests_test_client_server_SOURCES = tests/test_client_server.cpp
tests_test_client_server_LDADD = src/libzmq.la

tests_test_thread_safe_SOURCES = tests/test_thread_safe.cpp
tests_test_thread_safe_LDADD = src/libzmq.la

tests_test_timers_SOURCES = tests/test_timers.cpp
tests_test_timers_LDADD = src/libzmq.la

tests_test_radio_dish_SOURCES = tests/test_radio_dish.cpp
tests_test_radio_dish_LDADD = src/libzmq.la

tests_test_udp_SOURCES = tests/test_udp.cpp
tests_test_udp_LDADD = src/libzmq.la

tests_test_scatter_gather_SOURCES = tests/test_scatter_gather.cpp
tests_test_scatter_gather_LDADD = src/libzmq.la

tests_test_dgram_SOURCES = tests/test_dgram.cpp
tests_test_dgram_LDADD = src/libzmq.la
endif

check_PROGRAMS = ${test_apps}

#  Run the test cases
TESTS = $(test_apps)
XFAIL_TESTS =

if !ON_LINUX
XFAIL_TESTS += tests/test_abstract_ipc
endif

if ON_GNU
XFAIL_TESTS += test_ipc_wildcard \
		test_term_endpoint
endif

EXTRA_DIST = \
	FindSodium.cmake \
	CMakeLists.txt \
	autogen.sh	\
	version.sh	\
	src/libzmq.pc.cmake.in \
	src/libzmq.vers \
	src/version.rc.in \
	tests/CMakeLists.txt \
	tools/curve_keygen.cpp

MAINTAINERCLEANFILES = \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/autom4te.cache \
	$(srcdir)/configure \
	`find "$(srcdir)" -type f -name Makefile.in -print`

@CODE_COVERAGE_RULES@

dist-hook:
	-rm $(distdir)/src/platform.hpp
	@if test -d "$(srcdir)/.git"; \
	then \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generated by Makefile. Do not edit.'; echo; \
		  $(top_srcdir)/config/missing --run git log --stat ) > ChangeLog.tmp \
		  && mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		  || ( rm -f ChangeLog.tmp ; \
		       echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

maintainer-clean-local:
	-rm -rf $(top_srcdir)/config

@VALGRIND_CHECK_RULES@

VALGRIND_SUPPRESSIONS_FILES = builds/valgrind/valgrind.supp
