ACLOCAL_AMFLAGS = -I config

SUBDIRS = doc

DIST_SUBDIRS = builds/msvc doc

pkgconfig_DATA = src/libzmq.pc

AM_CPPFLAGS = \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/include

#
# libraries/binaries
#
lib_LTLIBRARIES = libzmq.la

include_HEADERS = \
	include/zmq.h \
	include/zmq_utils.h

libzmq_la_SOURCES = \
	src/address.cpp \
	src/address.hpp \
	src/array.hpp \
	src/atomic_counter.hpp \
	src/atomic_ptr.hpp \
	src/blob.hpp \
	src/clock.cpp \
	src/clock.hpp \
	src/command.hpp \
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
	src/gssapi_mechanism_base.cpp \
	src/gssapi_mechanism_base.hpp \
	src/gssapi_client.cpp \
	src/gssapi_client.hpp \
	src/gssapi_server.cpp \
	src/gssapi_server.hpp \
	src/i_encoder.hpp \
	src/i_engine.hpp \
	src/i_decoder.hpp \
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
	src/mailbox.cpp \
	src/mailbox.hpp \
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
	src/proxy.cpp \
	src/proxy.hpp \
	src/pub.cpp \
	src/pub.hpp \
	src/pull.cpp \
	src/pull.hpp \
	src/push.cpp \
	src/push.hpp \
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
	src/select.cpp \
	src/select.hpp \
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
	src/tipc_address.cpp \
	src/tipc_address.hpp \
	src/tipc_connecter.cpp \
	src/tipc_connecter.hpp \
	src/tipc_listener.cpp \
	src/tipc_listener.hpp \
	src/trie.cpp \
	src/trie.hpp \
	src/v1_decoder.cpp \
	src/v1_decoder.hpp \
	src/v2_decoder.cpp \
	src/v2_decoder.hpp \
	src/v1_encoder.cpp \
	src/v1_encoder.hpp \
	src/v2_encoder.cpp \
	src/v2_encoder.hpp \
	src/v2_protocol.hpp \
	src/windows.hpp \
	src/wire.hpp \
	src/xpub.hpp \
	src/xpub.cpp \
	src/xsub.cpp \
	src/xsub.hpp \
	src/ypipe.hpp \
	src/ypipe_base.hpp \
	src/ypipe_conflate.hpp \
	src/yqueue.hpp \
	src/zmq.cpp \
	src/zmq_utils.cpp

if ON_MINGW
libzmq_la_LDFLAGS = \
	-no-undefined \
	-avoid-version \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
else
if ON_ANDROID
libzmq_la_LDFLAGS = \
	-avoid-version \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@
else
if ON_LINUX
libzmq_la_LDFLAGS = \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@ \
	-Wl,--version-script=$(srcdir)/src/libzmq.vers
else
libzmq_la_LDFLAGS = \
	-version-info @LTVER@ \
	@LIBZMQ_EXTRA_LDFLAGS@ \
	-Wl
endif
endif
endif

libzmq_la_CPPFLAGS =
libzmq_la_CXXFLAGS = @LIBZMQ_EXTRA_CXXFLAGS@
libzmq_la_LIBADD =

if HAVE_SODIUM
libzmq_la_CPPFLAGS += ${sodium_CFLAGS}
libzmq_la_LIBADD += ${sodium_LIBS}
endif

if HAVE_PGM
libzmq_la_CPPFLAGS += ${pgm_CFLAGS}
libzmq_la_LIBADD += ${pgm_LIBS}
endif

noinst_PROGRAMS = \
	local_lat \
	remote_lat \
	local_thr \
	remote_thr \
	inproc_lat \
	inproc_thr

local_lat_LDADD = libzmq.la
local_lat_SOURCES = perf/local_lat.cpp

remote_lat_LDADD = libzmq.la
remote_lat_SOURCES = perf/remote_lat.cpp

local_thr_LDADD = libzmq.la
local_thr_SOURCES = perf/local_thr.cpp

remote_thr_LDADD = libzmq.la
remote_thr_SOURCES = perf/remote_thr.cpp

inproc_lat_LDADD = libzmq.la
inproc_lat_SOURCES = perf/inproc_lat.cpp

inproc_thr_LDADD = libzmq.la
inproc_thr_SOURCES = perf/inproc_thr.cpp

bin_PROGRAMS = curve_keygen

curve_keygen_LDADD = libzmq.la
curve_keygen_SOURCES = tools/curve_keygen.cpp

#
# tests
#
test_apps = \
	test_system \
	test_pair_inproc \
	test_pair_tcp \
	test_reqrep_inproc \
	test_reqrep_tcp \
	test_hwm \
	test_hwm_pubsub \
	test_reqrep_device \
	test_sub_forward \
	test_invalid_rep \
	test_msg_flags \
	test_connect_resolve \
	test_immediate \
	test_last_endpoint \
	test_term_endpoint \
	test_srcfd \
	test_monitor \
	test_router_mandatory \
	test_router_mandatory_hwm \
	test_router_handover \
	test_probe_router \
	test_stream \
	test_stream_empty \
	test_stream_disconnect \
	test_stream_timeout \
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
	test_proxy \
	test_many_sockets \
	test_ipc_wildcard \
	test_diffserv \
	test_connect_rid \
	test_bind_src_address \
	test_metadata \
	test_id2fd \
	test_capabilities \
	test_xpub_nodrop

test_system_SOURCES = tests/test_system.cpp
test_system_LDADD = libzmq.la

test_pair_inproc_SOURCES = \
	tests/test_pair_inproc.cpp \
	tests/testutil.hpp
test_pair_inproc_LDADD = libzmq.la

test_pair_tcp_SOURCES = \
	tests/test_pair_tcp.cpp \
	tests/testutil.hpp
test_pair_tcp_LDADD = libzmq.la

test_reqrep_inproc_SOURCES = \
	tests/test_reqrep_inproc.cpp \
	tests/testutil.hpp
test_reqrep_inproc_LDADD = libzmq.la

test_reqrep_tcp_SOURCES = \
	tests/test_reqrep_tcp.cpp \
	tests/testutil.hpp
test_reqrep_tcp_LDADD = libzmq.la

test_hwm_SOURCES = tests/test_hwm.cpp
test_hwm_LDADD = libzmq.la

test_hwm_pubsub_SOURCES = tests/test_hwm_pubsub.cpp
test_hwm_pubsub_LDADD = libzmq.la

test_reqrep_device_SOURCES = tests/test_reqrep_device.cpp
test_reqrep_device_LDADD = libzmq.la

test_sub_forward_SOURCES = tests/test_sub_forward.cpp
test_sub_forward_LDADD = libzmq.la

test_invalid_rep_SOURCES = tests/test_invalid_rep.cpp
test_invalid_rep_LDADD = libzmq.la

test_msg_flags_SOURCES = tests/test_msg_flags.cpp
test_msg_flags_LDADD = libzmq.la

test_connect_resolve_SOURCES = tests/test_connect_resolve.cpp
test_connect_resolve_LDADD = libzmq.la

test_immediate_SOURCES = tests/test_immediate.cpp
test_immediate_LDADD = libzmq.la

test_last_endpoint_SOURCES = tests/test_last_endpoint.cpp
test_last_endpoint_LDADD = libzmq.la

test_term_endpoint_SOURCES = tests/test_term_endpoint.cpp
test_term_endpoint_LDADD = libzmq.la

test_srcfd_SOURCES = tests/test_srcfd.cpp
test_srcfd_LDADD = libzmq.la

test_monitor_SOURCES = tests/test_monitor.cpp
test_monitor_LDADD = libzmq.la

test_router_mandatory_SOURCES = tests/test_router_mandatory.cpp
test_router_mandatory_LDADD = libzmq.la

test_router_mandatory_hwm_SOURCES = tests/test_router_mandatory_hwm.cpp
test_router_mandatory_hwm_LDADD = libzmq.la

test_router_handover_SOURCES = tests/test_router_handover.cpp
test_router_handover_LDADD = libzmq.la

test_probe_router_SOURCES = tests/test_probe_router.cpp
test_probe_router_LDADD = libzmq.la

test_stream_SOURCES = tests/test_stream.cpp
test_stream_LDADD = libzmq.la

test_stream_empty_SOURCES = tests/test_stream_empty.cpp
test_stream_empty_LDADD = libzmq.la

test_stream_timeout_SOURCES = tests/test_stream_timeout.cpp
test_stream_timeout_LDADD = libzmq.la

test_stream_disconnect_SOURCES = tests/test_stream_disconnect.cpp
test_stream_disconnect_LDADD = libzmq.la

test_disconnect_inproc_SOURCES = tests/test_disconnect_inproc.cpp
test_disconnect_inproc_LDADD = libzmq.la

test_ctx_options_SOURCES = tests/test_ctx_options.cpp
test_ctx_options_LDADD = libzmq.la

test_iov_SOURCES = tests/test_iov.cpp
test_iov_LDADD = libzmq.la

test_ctx_destroy_SOURCES = tests/test_ctx_destroy.cpp
test_ctx_destroy_LDADD = libzmq.la

test_security_null_SOURCES = tests/test_security_null.cpp
test_security_null_LDADD = libzmq.la

test_security_plain_SOURCES = tests/test_security_plain.cpp
test_security_plain_LDADD = libzmq.la

test_security_curve_SOURCES = tests/test_security_curve.cpp
test_security_curve_LDADD = libzmq.la

test_spec_req_SOURCES = tests/test_spec_req.cpp
test_spec_req_LDADD = libzmq.la

test_spec_rep_SOURCES = tests/test_spec_rep.cpp
test_spec_rep_LDADD = libzmq.la

test_spec_dealer_SOURCES = tests/test_spec_dealer.cpp
test_spec_dealer_LDADD = libzmq.la

test_spec_router_SOURCES = tests/test_spec_router.cpp
test_spec_router_LDADD = libzmq.la

test_spec_pushpull_SOURCES = tests/test_spec_pushpull.cpp
test_spec_pushpull_LDADD = libzmq.la

test_req_correlate_SOURCES = tests/test_req_correlate.cpp
test_req_correlate_LDADD = libzmq.la

test_req_relaxed_SOURCES = tests/test_req_relaxed.cpp
test_req_relaxed_LDADD = libzmq.la

test_conflate_SOURCES = tests/test_conflate.cpp
test_conflate_LDADD = libzmq.la

test_inproc_connect_SOURCES = tests/test_inproc_connect.cpp
test_inproc_connect_LDADD = libzmq.la

test_issue_566_SOURCES = tests/test_issue_566.cpp
test_issue_566_LDADD = libzmq.la

test_proxy_SOURCES = tests/test_proxy.cpp
test_proxy_LDADD = libzmq.la

test_many_sockets_SOURCES = tests/test_many_sockets.cpp
test_many_sockets_LDADD = libzmq.la

test_ipc_wildcard_SOURCES = tests/test_ipc_wildcard.cpp
test_ipc_wildcard_LDADD = libzmq.la

test_diffserv_SOURCES = tests/test_diffserv.cpp
test_diffserv_LDADD = libzmq.la

test_connect_rid_SOURCES = tests/test_connect_rid.cpp
test_connect_rid_LDADD = libzmq.la

test_bind_src_address_SOURCES = tests/test_bind_src_address.cpp
test_bind_src_address_LDADD = libzmq.la

test_metadata_SOURCES = tests/test_metadata.cpp
test_metadata_LDADD = libzmq.la

test_id2fd_SOURCES = tests/test_id2fd.cpp
test_id2fd_LDADD = libzmq.la

test_capabilities_SOURCES = tests/test_capabilities.cpp
test_capabilities_LDADD = libzmq.la

test_xpub_nodrop_SOURCES = tests/test_xpub_nodrop.cpp
test_xpub_nodrop_LDADD = libzmq.la

if !ON_MINGW
test_apps += \
	test_shutdown_stress \
	test_pair_ipc \
	test_reqrep_ipc \
	test_timeo \
	test_filter_ipc

test_shutdown_stress_SOURCES = tests/test_shutdown_stress.cpp
test_shutdown_stress_LDADD = libzmq.la

test_pair_ipc_SOURCES = \
	tests/test_pair_ipc.cpp \
	tests/testutil.hpp
test_pair_ipc_LDADD = libzmq.la

test_reqrep_ipc_SOURCES = \
	tests/test_reqrep_ipc.cpp \
	tests/testutil.hpp
test_reqrep_ipc_LDADD = libzmq.la

test_timeo_SOURCES = tests/test_timeo.cpp
test_timeo_LDADD = libzmq.la

test_filter_ipc_SOURCES = tests/test_filter_ipc.cpp
test_filter_ipc_LDADD = libzmq.la

if HAVE_FORK
test_apps += test_fork

test_fork_SOURCES = tests/test_fork.cpp
test_fork_LDADD = libzmq.la

endif
endif

if BUILD_TIPC
test_apps += \
	test_connect_delay_tipc \
	test_pair_tipc \
	test_reqrep_device_tipc \
	test_reqrep_tipc \
	test_router_mandatory_tipc \
	test_shutdown_stress_tipc \
	test_sub_forward_tipc \
	test_term_endpoint_tipc

test_connect_delay_tipc_SOURCES = tests/test_connect_delay_tipc.cpp
test_connect_delay_tipc_LDADD = libzmq.la

test_pair_tipc_SOURCES = tests/test_pair_tipc.cpp
test_pair_tipc_LDADD = libzmq.la

test_reqrep_device_tipc_SOURCES = tests/test_reqrep_device_tipc.cpp
test_reqrep_device_tipc_LDADD = libzmq.la

test_reqrep_tipc_SOURCES = tests/test_reqrep_tipc.cpp
test_reqrep_tipc_LDADD = libzmq.la

test_router_mandatory_tipc_SOURCES = tests/test_router_mandatory_tipc.cpp
test_router_mandatory_tipc_LDADD = libzmq.la

test_shutdown_stress_tipc_SOURCES = tests/test_shutdown_stress_tipc.cpp
test_shutdown_stress_tipc_LDADD = libzmq.la

test_sub_forward_tipc_SOURCES = tests/test_sub_forward_tipc.cpp
test_sub_forward_tipc_LDADD = libzmq.la

test_term_endpoint_tipc_SOURCES = tests/test_term_endpoint_tipc.cpp
test_term_endpoint_tipc_LDADD = libzmq.la

endif

if ON_LINUX
test_apps += test_abstract_ipc

test_abstract_ipc_SOURCES = tests/test_abstract_ipc.cpp
test_abstract_ipc_LDADD = libzmq.la

endif

check_PROGRAMS = ${test_apps}

#  Run the test cases
TESTS = $(test_apps)
XFAIL_TESTS =

if !ON_LINUX
XFAIL_TESTS += test_abstract_ipc
endif

EXTRA_DIST = \
	CMakeLists.txt \
	autogen.sh	\
	version.sh	\
	MAINTAINERS	\
	src/libzmq.pc.cmake.in \
	src/libzmq.vers \
	tools/curve_keygen.cpp

MAINTAINERCLEANFILES = \
	$(srcdir)/aclocal.m4 \
	$(srcdir)/autom4te.cache \
	$(srcdir)/configure \
	`find "$(srcdir)" -type f -name Makefile.in -print`

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
	-cp $(top_srcdir)/builds/redhat/zeromq.spec $(distdir)/zeromq.spec

maintainer-clean-local:
	-rm -rf $(top_srcdir)/config

