ACLOCAL_AMFLAGS = -I config

SUBDIRS = doc

DIST_SUBDIRS = doc builds builds/deprecated-msvc

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
	src/channel.cpp \
	src/channel.hpp \
	src/client.cpp \
	src/client.hpp \
	src/clock.cpp \
	src/clock.hpp \
	src/command.hpp \
	src/compat.hpp \
	src/condition_variable.hpp \
	src/config.hpp \
	src/ctx.cpp \
	src/ctx.hpp \
	src/curve_client.cpp \
	src/curve_client.hpp \
	src/curve_client_tools.hpp \
	src/curve_mechanism_base.cpp \
	src/curve_mechanism_base.hpp \
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
	src/endpoint.hpp \
	src/endpoint.cpp \
	src/epoll.cpp \
	src/epoll.hpp \
	src/err.cpp \
	src/err.hpp \
	src/fd.hpp \
	src/fq.cpp \
	src/fq.hpp \
	src/gather.cpp \
	src/gather.hpp \
	src/generic_mtrie.hpp \
	src/generic_mtrie_impl.hpp \
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
	src/ip_resolver.cpp \
	src/ip_resolver.hpp \
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
	src/mechanism_base.cpp \
	src/mechanism_base.hpp  \
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
	src/peer.cpp \
	src/peer.hpp \
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
	src/plain_common.hpp \
	src/plain_server.cpp \
	src/plain_server.hpp \
	src/platform.hpp \
	src/poll.cpp \
	src/poll.hpp \
	src/poller.hpp \
	src/poller_base.cpp \
	src/poller_base.hpp \
	src/polling_util.cpp \
	src/polling_util.hpp \
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
	src/radix_tree.cpp \
	src/radix_tree.hpp \
	src/random.cpp \
	src/random.hpp \
	src/raw_decoder.cpp \
	src/raw_decoder.hpp \
	src/raw_encoder.cpp \
	src/raw_encoder.hpp \
	src/raw_engine.cpp \
	src/raw_engine.hpp \
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
	src/secure_allocator.hpp \
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
	src/stream_connecter_base.cpp \
	src/stream_connecter_base.hpp \
	src/stream_listener_base.cpp \
	src/stream_listener_base.hpp \
	src/stream_engine_base.cpp \
	src/stream_engine_base.hpp \
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
	src/v3_1_encoder.cpp \
	src/v3_1_encoder.hpp \
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
	src/zap_client.cpp \
	src/zap_client.hpp \
	src/zmtp_engine.cpp \
	src/zmtp_engine.hpp \
	src/zmq_draft.h

if USE_WEPOLL
src_libzmq_la_SOURCES += \
	external/wepoll/wepoll.c \
	external/wepoll/wepoll.h
endif

if USE_TWEETNACL
src_libzmq_la_SOURCES += \
	src/tweetnacl.c \
	src/tweetnacl.h
endif

if HAVE_WS
src_libzmq_la_SOURCES += \
	src/ws_address.cpp \
	src/ws_address.hpp \
	src/wss_address.cpp \
	src/wss_address.hpp \
	src/ws_connecter.cpp \
	src/ws_connecter.hpp \
	src/ws_decoder.cpp \
	src/ws_decoder.hpp \
	src/ws_encoder.cpp \
	src/ws_encoder.hpp \
	src/ws_engine.cpp \
	src/ws_engine.hpp \
	src/ws_listener.cpp \
	src/ws_listener.hpp \
	src/ws_protocol.hpp
endif

if USE_BUILTIN_SHA1
src_libzmq_la_SOURCES += \
	external/sha1/sha1.c \
	external/sha1/sha1.h
endif

if HAVE_WSS
src_libzmq_la_SOURCES += \
	src/wss_engine.cpp \
	src/wss_engine.hpp
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
src_libzmq_la_LDFLAGS = \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
endif
endif
endif

if HAVE_VSCRIPT_COMPLEX
src_libzmq_la_LDFLAGS += $(VSCRIPT_LDFLAGS),$(srcdir)/src/libzmq.vers
endif

src_libzmq_la_CPPFLAGS = $(CODE_COVERAGE_CPPFLAGS) $(LIBUNWIND_CFLAGS) $(LIBBSD_CFLAGS)
src_libzmq_la_CFLAGS = $(CODE_COVERAGE_CFLAGS) $(LIBUNWIND_CFLAGS) $(LIBBSD_CFLAGS)
src_libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@ $(CODE_COVERAGE_CXXFLAGS) \
	$(LIBUNWIND_CFLAGS) $(LIBBSD_CFLAGS)
src_libzmq_la_LIBADD = $(CODE_COVERAGE_LDFLAGS) $(LIBUNWIND_LIBS) $(LIBBSD_LIBS)

if USE_NSS
src_libzmq_la_CPPFLAGS += ${NSS3_CFLAGS}
src_libzmq_la_LIBADD += ${NSS3_LIBS}
endif

if USE_GNUTLS
src_libzmq_la_CPPFLAGS += ${GNUTLS_CFLAGS}
src_libzmq_la_LIBADD += ${GNUTLS_LIBS}
endif

if USE_LIBSODIUM
src_libzmq_la_CPPFLAGS += ${sodium_CFLAGS}
src_libzmq_la_LIBADD += ${sodium_LIBS}
endif

if HAVE_PGM
src_libzmq_la_CPPFLAGS += ${pgm_CFLAGS}
src_libzmq_la_LIBADD += ${pgm_LIBS}
endif

if HAVE_NORM
src_libzmq_la_CPPFLAGS += ${norm_CFLAGS}
src_libzmq_la_LIBADD += ${norm_LIBS}
endif

if BUILD_GSSAPI
src_libzmq_la_CPPFLAGS += ${gssapi_krb5_CFLAGS}
src_libzmq_la_LIBADD += ${gssapi_krb5_LIBS}
endif

if ENABLE_PERF
noinst_PROGRAMS = \
	perf/local_lat \
	perf/remote_lat \
	perf/local_thr \
	perf/remote_thr \
	perf/inproc_lat \
	perf/inproc_thr \
	perf/proxy_thr

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

perf_proxy_thr_LDADD = src/libzmq.la
perf_proxy_thr_SOURCES = perf/proxy_thr.cpp

if ENABLE_STATIC
noinst_PROGRAMS += \
	perf/benchmark_radix_tree

perf_benchmark_radix_tree_DEPENDENCIES = src/libzmq.la
perf_benchmark_radix_tree_CPPFLAGS = -I$(top_srcdir)/src
perf_benchmark_radix_tree_LDADD = $(top_builddir)/src/.libs/libzmq.a \
	${src_libzmq_la_LIBADD}
perf_benchmark_radix_tree_SOURCES = perf/benchmark_radix_tree.cpp
endif
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
	tests/test_unbind_wildcard \
	tests/test_ctx_options \
	tests/test_ctx_destroy \
        tests/test_security_no_zap_handler \
        tests/test_security_null \
	tests/test_security_plain \
	tests/test_security_zap \
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
	tests/test_proxy_hwm \
	tests/test_proxy_single_socket \
	tests/test_proxy_terminate \
	tests/test_getsockopt_memset \
	tests/test_setsockopt \
	tests/test_diffserv \
	tests/test_connect_rid \
	tests/test_bind_src_address \
	tests/test_metadata \
	tests/test_capabilities \
	tests/test_xpub_nodrop \
	tests/test_xpub_manual \
	tests/test_xpub_welcome_msg \
	tests/test_xpub_verbose \
	tests/test_atomics \
	tests/test_sockopt_hwm \
	tests/test_heartbeats \
	tests/test_stream_exceeds_buffer \
	tests/test_pub_invert_matching \
	tests/test_base85 \
	tests/test_bind_after_connect_tcp \
	tests/test_sodium \
	tests/test_reconnect_ivl \
	tests/test_mock_pub_sub \
	tests/test_socket_null \
	tests/test_tcp_accept_filter

UNITY_CPPFLAGS = -I$(top_srcdir)/external/unity -DUNITY_USE_COMMAND_LINE_ARGS -DUNITY_EXCLUDE_FLOAT
UNITY_LIBS = $(top_builddir)/external/unity/libunity.a
external_unity_libunity_a_SOURCES = external/unity/unity.c \
	external/unity/unity.h \
	external/unity/unity_internals.h

TESTUTIL_CPPFLAGS = ${UNITY_CPPFLAGS}
TESTUTIL_LIBS = $(top_builddir)/tests/libtestutil.a ${UNITY_LIBS}
tests_libtestutil_a_SOURCES = \
        tests/testutil.cpp \
        tests/testutil.hpp \
        tests/testutil_monitoring.cpp \
        tests/testutil_monitoring.hpp \
        tests/testutil_security.cpp \
        tests/testutil_security.hpp \
        tests/testutil_unity.cpp \
        tests/testutil_unity.hpp
tests_libtestutil_a_CPPFLAGS = ${UNITY_CPPFLAGS}

noinst_LIBRARIES = external/unity/libunity.a tests/libtestutil.a

tests_test_ancillaries_SOURCES = tests/test_ancillaries.cpp
tests_test_ancillaries_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_ancillaries_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_system_SOURCES = tests/test_system.cpp
tests_test_system_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_system_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_pair_inproc_SOURCES = tests/test_pair_inproc.cpp
tests_test_pair_inproc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pair_inproc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_pair_tcp_SOURCES = tests/test_pair_tcp.cpp
tests_test_pair_tcp_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pair_tcp_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_inproc_SOURCES = tests/test_reqrep_inproc.cpp
tests_test_reqrep_inproc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_inproc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_tcp_SOURCES = tests/test_reqrep_tcp.cpp
tests_test_reqrep_tcp_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_tcp_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_hwm_SOURCES = tests/test_hwm.cpp
tests_test_hwm_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_hwm_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_hwm_pubsub_SOURCES = tests/test_hwm_pubsub.cpp
tests_test_hwm_pubsub_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_hwm_pubsub_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_device_SOURCES = tests/test_reqrep_device.cpp
tests_test_reqrep_device_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_device_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_sub_forward_SOURCES = tests/test_sub_forward.cpp
tests_test_sub_forward_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_sub_forward_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_invalid_rep_SOURCES = tests/test_invalid_rep.cpp
tests_test_invalid_rep_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_invalid_rep_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_msg_flags_SOURCES = tests/test_msg_flags.cpp
tests_test_msg_flags_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_msg_flags_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_msg_ffn_SOURCES = tests/test_msg_ffn.cpp
tests_test_msg_ffn_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_msg_ffn_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_resolve_SOURCES = tests/test_connect_resolve.cpp
tests_test_connect_resolve_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_resolve_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_immediate_SOURCES = tests/test_immediate.cpp
tests_test_immediate_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_immediate_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_last_endpoint_SOURCES = tests/test_last_endpoint.cpp
tests_test_last_endpoint_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_last_endpoint_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_term_endpoint_SOURCES = tests/test_term_endpoint.cpp
tests_test_term_endpoint_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_term_endpoint_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_srcfd_SOURCES = tests/test_srcfd.cpp
tests_test_srcfd_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_srcfd_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_monitor_SOURCES = tests/test_monitor.cpp
tests_test_monitor_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_monitor_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_router_mandatory_SOURCES = tests/test_router_mandatory.cpp
tests_test_router_mandatory_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_router_mandatory_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_router_mandatory_hwm_SOURCES = tests/test_router_mandatory_hwm.cpp
tests_test_router_mandatory_hwm_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_router_mandatory_hwm_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_router_handover_SOURCES = tests/test_router_handover.cpp
tests_test_router_handover_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_router_handover_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_probe_router_SOURCES = tests/test_probe_router.cpp
tests_test_probe_router_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_probe_router_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_stream_SOURCES = tests/test_stream.cpp
tests_test_stream_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_stream_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_stream_empty_SOURCES = tests/test_stream_empty.cpp
tests_test_stream_empty_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_stream_empty_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_stream_timeout_SOURCES = tests/test_stream_timeout.cpp
tests_test_stream_timeout_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_stream_timeout_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_stream_disconnect_SOURCES = tests/test_stream_disconnect.cpp
tests_test_stream_disconnect_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_stream_disconnect_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_disconnect_inproc_SOURCES = tests/test_disconnect_inproc.cpp
tests_test_disconnect_inproc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_disconnect_inproc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_unbind_wildcard_SOURCES = tests/test_unbind_wildcard.cpp
tests_test_unbind_wildcard_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_unbind_wildcard_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_ctx_options_SOURCES = tests/test_ctx_options.cpp
tests_test_ctx_options_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_ctx_options_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_iov_SOURCES = tests/test_iov.cpp
tests_test_iov_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_iov_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_ctx_destroy_SOURCES = tests/test_ctx_destroy.cpp
tests_test_ctx_destroy_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_ctx_destroy_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_security_no_zap_handler_SOURCES = tests/test_security_no_zap_handler.cpp
tests_test_security_no_zap_handler_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_security_no_zap_handler_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_security_null_SOURCES = tests/test_security_null.cpp
tests_test_security_null_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_security_null_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_security_plain_SOURCES = tests/test_security_plain.cpp
tests_test_security_plain_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_security_plain_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_security_zap_SOURCES = tests/test_security_zap.cpp
tests_test_security_zap_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_security_zap_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_spec_req_SOURCES = tests/test_spec_req.cpp
tests_test_spec_req_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_spec_req_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_spec_rep_SOURCES = tests/test_spec_rep.cpp
tests_test_spec_rep_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_spec_rep_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_spec_dealer_SOURCES = tests/test_spec_dealer.cpp
tests_test_spec_dealer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_spec_dealer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_spec_router_SOURCES = tests/test_spec_router.cpp
tests_test_spec_router_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_spec_router_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_spec_pushpull_SOURCES = tests/test_spec_pushpull.cpp
tests_test_spec_pushpull_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_spec_pushpull_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_req_correlate_SOURCES = tests/test_req_correlate.cpp
tests_test_req_correlate_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_req_correlate_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_req_relaxed_SOURCES = tests/test_req_relaxed.cpp
tests_test_req_relaxed_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_req_relaxed_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_conflate_SOURCES = tests/test_conflate.cpp
tests_test_conflate_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_conflate_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_inproc_connect_SOURCES = tests/test_inproc_connect.cpp
tests_test_inproc_connect_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_inproc_connect_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_issue_566_SOURCES = tests/test_issue_566.cpp
tests_test_issue_566_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_issue_566_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_proxy_SOURCES = tests/test_proxy.cpp
tests_test_proxy_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_proxy_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_proxy_hwm_SOURCES = tests/test_proxy_hwm.cpp
tests_test_proxy_hwm_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_proxy_hwm_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_proxy_single_socket_SOURCES = tests/test_proxy_single_socket.cpp
tests_test_proxy_single_socket_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_proxy_single_socket_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_proxy_terminate_SOURCES = tests/test_proxy_terminate.cpp
tests_test_proxy_terminate_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_proxy_terminate_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_getsockopt_memset_SOURCES = tests/test_getsockopt_memset.cpp
tests_test_getsockopt_memset_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_getsockopt_memset_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_diffserv_SOURCES = tests/test_diffserv.cpp
tests_test_diffserv_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_diffserv_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_rid_SOURCES = tests/test_connect_rid.cpp
tests_test_connect_rid_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_rid_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_bind_src_address_SOURCES = tests/test_bind_src_address.cpp
tests_test_bind_src_address_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_src_address_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_metadata_SOURCES = tests/test_metadata.cpp
tests_test_metadata_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_metadata_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_capabilities_SOURCES = tests/test_capabilities.cpp
tests_test_capabilities_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_capabilities_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_xpub_nodrop_SOURCES = tests/test_xpub_nodrop.cpp
tests_test_xpub_nodrop_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_xpub_nodrop_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_xpub_manual_SOURCES = tests/test_xpub_manual.cpp
tests_test_xpub_manual_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_xpub_manual_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_xpub_welcome_msg_SOURCES = tests/test_xpub_welcome_msg.cpp
tests_test_xpub_welcome_msg_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_xpub_welcome_msg_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_xpub_verbose_SOURCES = tests/test_xpub_verbose.cpp
tests_test_xpub_verbose_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_xpub_verbose_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_atomics_SOURCES = tests/test_atomics.cpp
tests_test_atomics_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_atomics_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_sockopt_hwm_SOURCES = tests/test_sockopt_hwm.cpp
tests_test_sockopt_hwm_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_sockopt_hwm_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_setsockopt_SOURCES = tests/test_setsockopt.cpp
tests_test_setsockopt_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_setsockopt_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_heartbeats_SOURCES = tests/test_heartbeats.cpp
tests_test_heartbeats_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_heartbeats_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_stream_exceeds_buffer_SOURCES = tests/test_stream_exceeds_buffer.cpp
tests_test_stream_exceeds_buffer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_stream_exceeds_buffer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_pub_invert_matching_SOURCES = tests/test_pub_invert_matching.cpp
tests_test_pub_invert_matching_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pub_invert_matching_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_bind_after_connect_tcp_SOURCES = tests/test_bind_after_connect_tcp.cpp
tests_test_bind_after_connect_tcp_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_after_connect_tcp_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_base85_SOURCES = tests/test_base85.cpp
tests_test_base85_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_base85_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_sodium_SOURCES = tests/test_sodium.cpp
tests_test_sodium_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_sodium_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_socket_null_SOURCES = tests/test_socket_null.cpp
tests_test_socket_null_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_socket_null_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reconnect_ivl_SOURCES = tests/test_reconnect_ivl.cpp
tests_test_reconnect_ivl_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reconnect_ivl_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_mock_pub_sub_SOURCES = tests/test_mock_pub_sub.cpp
tests_test_mock_pub_sub_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_mock_pub_sub_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_tcp_accept_filter_SOURCES = tests/test_tcp_accept_filter.cpp
tests_test_tcp_accept_filter_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_tcp_accept_filter_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

if HAVE_CURVE

test_apps += \
	tests/test_security_curve

tests_test_security_curve_SOURCES = \
	tests/test_security_curve.cpp \
        src/curve_client_tools.hpp \
	src/clock.hpp \
	src/clock.cpp \
	src/random.hpp \
	src/random.cpp \
	src/err.hpp \
	src/err.cpp

if USE_TWEETNACL
tests_test_security_curve_SOURCES += \
	src/tweetnacl.c
endif

tests_test_security_curve_LDADD = \
        ${TESTUTIL_LIBS} src/libzmq.la $(LIBUNWIND_LIBS) $(LIBBSD_LIBS)
tests_test_security_curve_CPPFLAGS = \
        ${TESTUTIL_CPPFLAGS} \
	${LIBUNWIND_CFLAGS}  ${LIBBSD_CFLAGS}

if USE_LIBSODIUM
tests_test_security_curve_CPPFLAGS += \
	${sodium_CFLAGS}
tests_test_security_curve_LDADD += \
	${sodium_LIBS}
endif

endif

if HAVE_WS
test_apps += \
	tests/test_ws_transport
tests_test_ws_transport_SOURCES = tests/test_ws_transport.cpp
tests_test_ws_transport_LDADD = ${TESTUTIL_LIBS} src/libzmq.la ${NSS3_LIBS}
tests_test_ws_transport_CPPFLAGS = ${TESTUTIL_CPPFLAGS} ${NSS3_CFLAGS}
endif

if HAVE_WSS
test_apps += \
	tests/test_wss_transport
tests_test_wss_transport_SOURCES = tests/test_wss_transport.cpp
tests_test_wss_transport_LDADD = ${TESTUTIL_LIBS} src/libzmq.la ${GNUTLS_LIBS}
tests_test_wss_transport_CPPFLAGS = ${TESTUTIL_CPPFLAGS} ${GNUTLS_CFLAGS}
endif

if !ON_MINGW
if !ON_CYGWIN
test_apps += \
	tests/test_shutdown_stress \
	tests/test_ipc_wildcard \
	tests/test_pair_ipc \
	tests/test_rebind_ipc \
	tests/test_reqrep_ipc \
	tests/test_use_fd \
	tests/test_zmq_poll_fd \
	tests/test_timeo \
	tests/test_filter_ipc

tests_test_shutdown_stress_SOURCES = tests/test_shutdown_stress.cpp
tests_test_shutdown_stress_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_shutdown_stress_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_ipc_wildcard_SOURCES = tests/test_ipc_wildcard.cpp
tests_test_ipc_wildcard_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_ipc_wildcard_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_pair_ipc_SOURCES = tests/test_pair_ipc.cpp
tests_test_pair_ipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pair_ipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_rebind_ipc_SOURCES = tests/test_rebind_ipc.cpp
tests_test_rebind_ipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_rebind_ipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_ipc_SOURCES = tests/test_reqrep_ipc.cpp
tests_test_reqrep_ipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_ipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_timeo_SOURCES = tests/test_timeo.cpp
tests_test_timeo_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_timeo_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_filter_ipc_SOURCES = tests/test_filter_ipc.cpp
tests_test_filter_ipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_filter_ipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_use_fd_SOURCES = tests/test_use_fd.cpp
tests_test_use_fd_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_use_fd_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_zmq_poll_fd_SOURCES = tests/test_zmq_poll_fd.cpp
tests_test_zmq_poll_fd_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_zmq_poll_fd_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

if HAVE_FORK
if !VALGRIND_ENABLED
test_apps += tests/test_fork

tests_test_fork_SOURCES = tests/test_fork.cpp
tests_test_fork_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_fork_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

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
	tests/test_term_endpoint_tipc \
	tests/test_address_tipc

tests_test_connect_delay_tipc_SOURCES = tests/test_connect_delay_tipc.cpp
tests_test_connect_delay_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_delay_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_pair_tipc_SOURCES = tests/test_pair_tipc.cpp
tests_test_pair_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pair_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_device_tipc_SOURCES = tests/test_reqrep_device_tipc.cpp
tests_test_reqrep_device_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_device_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reqrep_tipc_SOURCES = tests/test_reqrep_tipc.cpp
tests_test_reqrep_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_router_mandatory_tipc_SOURCES = tests/test_router_mandatory_tipc.cpp
tests_test_router_mandatory_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_router_mandatory_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_shutdown_stress_tipc_SOURCES = tests/test_shutdown_stress_tipc.cpp
tests_test_shutdown_stress_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_shutdown_stress_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_sub_forward_tipc_SOURCES = tests/test_sub_forward_tipc.cpp
tests_test_sub_forward_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_sub_forward_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_term_endpoint_tipc_SOURCES = tests/test_term_endpoint_tipc.cpp
tests_test_term_endpoint_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_term_endpoint_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_address_tipc_SOURCES = tests/test_address_tipc.cpp
tests_test_address_tipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_address_tipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

endif

if BUILD_GSSAPI
test_apps += tests/test_security_gssapi

tests_test_security_gssapi_SOURCES = tests/test_security_gssapi.cpp
tests_test_security_gssapi_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_security_gssapi_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

endif

if ON_LINUX
test_apps += tests/test_abstract_ipc \
	tests/test_socks

tests_test_abstract_ipc_SOURCES = tests/test_abstract_ipc.cpp
tests_test_abstract_ipc_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_abstract_ipc_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_socks_SOURCES = tests/test_socks.cpp
tests_test_socks_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_socks_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

# TODO: enable when https://github.com/zeromq/libzmq/issues/3898 is fixed
if !ENABLE_ASAN
test_apps += tests/test_many_sockets

tests_test_many_sockets_SOURCES = tests/test_many_sockets.cpp
tests_test_many_sockets_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_many_sockets_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
endif

endif

if HAVE_VMCI
test_apps += tests/test_pair_vmci tests/test_reqrep_vmci

tests_test_pair_vmci_SOURCES = tests/test_pair_vmci.cpp
tests_test_pair_vmci_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_pair_vmci_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_pair_vmci_LDFLAGS = @LIBZMQ_VMCI_LDFLAGS@
tests_test_pair_vmci_CXXFLAGS = @LIBZMQ_VMCI_CXXFLAGS@

tests_test_reqrep_vmci_SOURCES = tests/test_reqrep_vmci.cpp
tests_test_reqrep_vmci_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reqrep_vmci_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_reqrep_vmci_LDFLAGS = @LIBZMQ_VMCI_LDFLAGS@
tests_test_reqrep_vmci_CXXFLAGS = @LIBZMQ_VMCI_CXXFLAGS@

endif

if ENABLE_DRAFTS
test_apps += tests/test_poller \
	tests/test_client_server \
	tests/test_thread_safe \
	tests/test_timers \
	tests/test_radio_dish \
	tests/test_scatter_gather \
	tests/test_dgram \
	tests/test_app_meta \
	tests/test_xpub_manual_last_value \
	tests/test_router_notify \
	tests/test_peer \
	tests/test_reconnect_options \
	tests/test_msg_init \
	tests/test_hello_msg \
	tests/test_disconnect_msg \
	tests/test_channel

tests_test_poller_SOURCES = tests/test_poller.cpp
tests_test_poller_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_poller_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_client_server_SOURCES = tests/test_client_server.cpp
tests_test_client_server_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_client_server_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_thread_safe_SOURCES = tests/test_thread_safe.cpp
tests_test_thread_safe_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_thread_safe_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_timers_SOURCES = tests/test_timers.cpp
tests_test_timers_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_timers_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_radio_dish_SOURCES = tests/test_radio_dish.cpp
tests_test_radio_dish_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_radio_dish_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_scatter_gather_SOURCES = tests/test_scatter_gather.cpp
tests_test_scatter_gather_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_scatter_gather_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_dgram_SOURCES = tests/test_dgram.cpp
tests_test_dgram_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_dgram_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_xpub_manual_last_value_SOURCES = tests/test_xpub_manual_last_value.cpp
tests_test_xpub_manual_last_value_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_xpub_manual_last_value_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_app_meta_SOURCES = tests/test_app_meta.cpp
tests_test_app_meta_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_app_meta_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_router_notify_SOURCES = tests/test_router_notify.cpp
tests_test_router_notify_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_router_notify_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_peer_SOURCES = tests/test_peer.cpp
tests_test_peer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_peer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_reconnect_options_SOURCES = tests/test_reconnect_options.cpp
tests_test_reconnect_options_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_reconnect_options_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_msg_init_SOURCES = tests/test_msg_init.cpp
tests_test_msg_init_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_msg_init_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_hello_msg_SOURCES = tests/test_hello_msg.cpp
tests_test_hello_msg_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_hello_msg_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_disconnect_msg_SOURCES = tests/test_disconnect_msg.cpp
tests_test_disconnect_msg_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_disconnect_msg_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_channel_SOURCES = tests/test_channel.cpp
tests_test_channel_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_channel_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
endif

if FUZZING_ENGINE_LIB
fuzzer_apps = tests/test_bind_null_fuzzer \
	tests/test_connect_null_fuzzer \
	tests/test_bind_fuzzer \
	tests/test_connect_fuzzer \
	tests/test_bind_stream_fuzzer \
	tests/test_connect_stream_fuzzer \
	tests/test_socket_options_fuzzer

tests_test_bind_null_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_bind_null_fuzzer_SOURCES = tests/test_bind_null_fuzzer.cpp
tests_test_bind_null_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_bind_null_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_bind_null_fuzzer_CXXFLAGS = -std=c++11

tests_test_connect_null_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_connect_null_fuzzer_SOURCES = tests/test_connect_null_fuzzer.cpp
tests_test_connect_null_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_connect_null_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_connect_null_fuzzer_CXXFLAGS = -std=c++11

tests_test_bind_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_bind_fuzzer_SOURCES = tests/test_bind_fuzzer.cpp
tests_test_bind_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_bind_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_bind_fuzzer_CXXFLAGS = -std=c++11

tests_test_connect_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_connect_fuzzer_SOURCES = tests/test_connect_fuzzer.cpp
tests_test_connect_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_connect_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_connect_fuzzer_CXXFLAGS = -std=c++11

tests_test_socket_options_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_socket_options_fuzzer_SOURCES = tests/test_socket_options_fuzzer.cpp
tests_test_socket_options_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_socket_options_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_socket_options_fuzzer_CXXFLAGS = -std=c++11

tests_test_bind_stream_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_bind_stream_fuzzer_SOURCES = tests/test_bind_stream_fuzzer.cpp
tests_test_bind_stream_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_bind_stream_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_bind_stream_fuzzer_CXXFLAGS = -std=c++11

tests_test_connect_stream_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_connect_stream_fuzzer_SOURCES = tests/test_connect_stream_fuzzer.cpp
tests_test_connect_stream_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_connect_stream_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_connect_stream_fuzzer_CXXFLAGS = -std=c++11

if HAVE_CURVE
fuzzer_apps += tests/test_bind_curve_fuzzer \
	tests/test_connect_curve_fuzzer \
	tests/test_z85_decode_fuzzer

tests_test_bind_curve_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_bind_curve_fuzzer_SOURCES = tests/test_bind_curve_fuzzer.cpp
tests_test_bind_curve_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_bind_curve_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_bind_curve_fuzzer_CXXFLAGS = -std=c++11

tests_test_connect_curve_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_connect_curve_fuzzer_SOURCES = tests/test_connect_curve_fuzzer.cpp
tests_test_connect_curve_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_connect_curve_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_connect_curve_fuzzer_CXXFLAGS = -std=c++11

tests_test_z85_decode_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_z85_decode_fuzzer_SOURCES = tests/test_z85_decode_fuzzer.cpp
tests_test_z85_decode_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_z85_decode_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_z85_decode_fuzzer_CXXFLAGS = -std=c++11
endif

if HAVE_WS
fuzzer_apps += tests/test_connect_ws_fuzzer \
	tests/test_bind_ws_fuzzer

tests_test_connect_ws_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_connect_ws_fuzzer_SOURCES = tests/test_connect_ws_fuzzer.cpp
tests_test_connect_ws_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_connect_ws_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_connect_ws_fuzzer_CXXFLAGS = -std=c++11

tests_test_bind_ws_fuzzer_DEPENDENCIES = src/libzmq.la
tests_test_bind_ws_fuzzer_SOURCES = tests/test_bind_ws_fuzzer.cpp
tests_test_bind_ws_fuzzer_LDADD = ${TESTUTIL_LIBS} ${FUZZING_ENGINE_LIB} \
		$(top_builddir)/src/.libs/libzmq.a \
		${src_libzmq_la_LIBADD}
tests_test_bind_ws_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
tests_test_bind_ws_fuzzer_CXXFLAGS = -std=c++11
endif

FUZZINGdir = ${prefix}/${FUZZING_INSTALLDIR}
FUZZING_PROGRAMS = ${fuzzer_apps}
else
test_apps += tests/test_bind_null_fuzzer \
	tests/test_connect_null_fuzzer \
	tests/test_bind_fuzzer \
	tests/test_connect_fuzzer \
	tests/test_bind_stream_fuzzer \
	tests/test_connect_stream_fuzzer \
	tests/test_socket_options_fuzzer

tests_test_bind_null_fuzzer_SOURCES = tests/test_bind_null_fuzzer.cpp
tests_test_bind_null_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_null_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_null_fuzzer_SOURCES = tests/test_connect_null_fuzzer.cpp
tests_test_connect_null_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_null_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_bind_fuzzer_SOURCES = tests/test_bind_fuzzer.cpp
tests_test_bind_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_fuzzer_SOURCES = tests/test_connect_fuzzer.cpp
tests_test_connect_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_socket_options_fuzzer_SOURCES = tests/test_socket_options_fuzzer.cpp
tests_test_socket_options_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_socket_options_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_bind_stream_fuzzer_SOURCES = tests/test_bind_stream_fuzzer.cpp
tests_test_bind_stream_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_stream_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_stream_fuzzer_SOURCES = tests/test_connect_stream_fuzzer.cpp
tests_test_connect_stream_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_stream_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

if HAVE_CURVE
test_apps += tests/test_bind_curve_fuzzer \
	tests/test_connect_curve_fuzzer \
	tests/test_z85_decode_fuzzer

tests_test_bind_curve_fuzzer_SOURCES = tests/test_bind_curve_fuzzer.cpp
tests_test_bind_curve_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_curve_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_connect_curve_fuzzer_SOURCES = tests/test_connect_curve_fuzzer.cpp
tests_test_connect_curve_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_curve_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_z85_decode_fuzzer_SOURCES = tests/test_z85_decode_fuzzer.cpp
tests_test_z85_decode_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_z85_decode_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
endif

if HAVE_WS
test_apps += tests/test_connect_ws_fuzzer \
	tests/test_bind_ws_fuzzer

tests_test_connect_ws_fuzzer_SOURCES = tests/test_connect_ws_fuzzer.cpp
tests_test_connect_ws_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_connect_ws_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}

tests_test_bind_ws_fuzzer_SOURCES = tests/test_bind_ws_fuzzer.cpp
tests_test_bind_ws_fuzzer_LDADD = ${TESTUTIL_LIBS} src/libzmq.la
tests_test_bind_ws_fuzzer_CPPFLAGS = ${TESTUTIL_CPPFLAGS}
endif
endif

if ENABLE_STATIC
# unit tests - these include individual source files and test the internal functions
test_apps += \
	unittests/unittest_poller \
	unittests/unittest_ypipe \
	unittests/unittest_mtrie \
	unittests/unittest_ip_resolver \
	unittests/unittest_udp_address \
	unittests/unittest_radix_tree \
	unittests/unittest_curve_encoding

unittests_unittest_poller_SOURCES = unittests/unittest_poller.cpp
unittests_unittest_poller_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_poller_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_poller_LDADD = \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_ypipe_SOURCES = unittests/unittest_ypipe.cpp
unittests_unittest_ypipe_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_ypipe_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_ypipe_LDADD = \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_mtrie_SOURCES = unittests/unittest_mtrie.cpp
unittests_unittest_mtrie_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_mtrie_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_mtrie_LDADD = \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_ip_resolver_SOURCES = unittests/unittest_ip_resolver.cpp unittests/unittest_resolver_common.hpp
unittests_unittest_ip_resolver_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_ip_resolver_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_ip_resolver_LDADD = \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_udp_address_SOURCES = unittests/unittest_udp_address.cpp unittests/unittest_resolver_common.hpp
unittests_unittest_udp_address_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_udp_address_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_udp_address_LDADD = \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_radix_tree_SOURCES = unittests/unittest_radix_tree.cpp
unittests_unittest_radix_tree_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_radix_tree_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_radix_tree_LDADD =  \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)

unittests_unittest_curve_encoding_SOURCES = unittests/unittest_curve_encoding.cpp
unittests_unittest_curve_encoding_CPPFLAGS = -I$(top_srcdir)/src ${TESTUTIL_CPPFLAGS} $(CODE_COVERAGE_CPPFLAGS)
unittests_unittest_curve_encoding_CXXFLAGS = $(CODE_COVERAGE_CXXFLAGS)
unittests_unittest_curve_encoding_LDADD =  \
        ${TESTUTIL_LIBS} \
        $(top_builddir)/src/.libs/libzmq.a \
        ${src_libzmq_la_LIBADD} \
        $(CODE_COVERAGE_LDFLAGS)
endif

check_PROGRAMS = ${test_apps}

#  Run the test cases
TESTS = $(test_apps)
XFAIL_TESTS =

if !ON_LINUX
XFAIL_TESTS += tests/test_abstract_ipc
endif

#  GNU/Hurd does not support getsockname on IPC, so ZMQ_LAST_ENDPOINT cannot be
#  used with IPC, so the following tests will fail
if ON_GNU
XFAIL_TESTS += tests/test_ipc_wildcard \
		tests/test_reqrep_ipc \
		tests/test_pair_ipc \
		tests/test_term_endpoint
endif

EXTRA_DIST = \
	external/unity/license.txt \
	external/unity/version.txt \
	external/wepoll/license.txt \
	external/wepoll/version.txt \
	external/wepoll/README.md \
	CMakeLists.txt \
	autogen.sh	\
	version.sh	\
	ci_build.sh \
	src/libzmq.vers \
	src/version.rc.in \
	tests/CMakeLists.txt \
        tests/test_pair_tcp_cap_net_admin.cpp \
	unittests/CMakeLists.txt \
        tools/curve_keygen.cpp

MAINTAINERCLEANFILES = \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/autom4te.cache \
	$(srcdir)/configure \
	`find "$(srcdir)" -type f -name Makefile.in -print`

if WITH_CLANG_FORMAT
ALL_SOURCE_FILES = $(wildcard \
	$(top_srcdir)/src/*.c \
	$(top_srcdir)/src/*.cc \
	$(top_srcdir)/src/*.cpp \
	$(top_srcdir)/src/*.h \
	$(top_srcdir)/src/*.hpp \
	$(top_srcdir)/tests/*.c \
	$(top_srcdir)/tests/*.cc \
	$(top_srcdir)/tests/*.cpp \
	$(top_srcdir)/tests/*.h \
	$(top_srcdir)/tests/*.hpp \
	$(top_srcdir)/perf/*.c \
	$(top_srcdir)/perf/*.cc \
	$(top_srcdir)/perf/*.cpp \
	$(top_srcdir)/perf/*.h \
	$(top_srcdir)/perf/*.hpp \
	$(top_srcdir)/tools/*.c \
	$(top_srcdir)/tools/*.cc \
	$(top_srcdir)/tools/*.cpp \
	$(top_srcdir)/tools/*.h \
	$(top_srcdir)/tools/*.hpp \
	$(top_srcdir)/include/*.h \
 )

# Check if any sources need to be fixed, report the filenames and an error code
clang-format-check: $(ALL_SOURCE_FILES)
	@FAILED=0 ; IFS=";" ; IDS="`printf '\n\b'`" ; export IFS IDS; \
	 for FILE in $(ALL_SOURCE_FILES) ; do \
		test -s $$FILE || continue ; \
		$(CLANG_FORMAT) -style=file -output-replacements-xml "$$FILE" | grep "<replacement " >/dev/null && \
		{ echo "$$FILE is not correctly formatted" >&2 ; FAILED=1; } ; \
	 done; \
	 if test "$$FAILED" != 0 ; then \
		exit 1 ; \
	 fi

# Change source formatting
clang-format: $(ALL_SOURCE_FILES)
	$(CLANG_FORMAT) -style=file -i $(ALL_SOURCE_FILES)

# Change source formatting AND report the diff
clang-format-diff: clang-format
	git diff $(ALL_SOURCE_FILES)

else
clang-format clang-format-check clang-format-diff:
	@echo "Install the clang-format program, reconfigure and re-run this request"
	@exit 1
endif

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
