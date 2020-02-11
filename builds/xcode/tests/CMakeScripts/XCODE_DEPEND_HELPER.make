# DO NOT EDIT
# This makefile makes sure all linkable targets are
# up-to-date with anything they link to
default:
	echo "Do not invoke directly"

# Rules to remove targets that are older than anything to which they
# link.  This forces Xcode to relink the targets from scratch.  It
# does not seem to check these dependencies itself.
PostBuild.test_ancillaries.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ancillaries
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ancillaries
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ancillaries
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ancillaries:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ancillaries


PostBuild.test_app_meta.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_app_meta
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_app_meta
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_app_meta
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_app_meta:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_app_meta


PostBuild.test_atomics.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_atomics
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_atomics
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_atomics
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_atomics:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_atomics


PostBuild.test_base85.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_base85
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_base85
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_base85
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_base85:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_base85


PostBuild.test_bind_after_connect_tcp.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_after_connect_tcp
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_after_connect_tcp
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_after_connect_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_after_connect_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_after_connect_tcp


PostBuild.test_bind_src_address.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_src_address
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_src_address
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_src_address
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_src_address:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_bind_src_address


PostBuild.test_capabilities.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_capabilities
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_capabilities
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_capabilities
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_capabilities:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_capabilities


PostBuild.test_client_server.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_client_server
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_client_server
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_client_server
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_client_server:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_client_server


PostBuild.test_conflate.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_conflate
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_conflate
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_conflate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_conflate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_conflate


PostBuild.test_connect_resolve.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_resolve
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_resolve
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_resolve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_resolve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_resolve


PostBuild.test_connect_rid.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_rid
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_rid
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_rid
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_rid:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_connect_rid


PostBuild.test_ctx_destroy.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_destroy
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_destroy
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_destroy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_destroy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_destroy


PostBuild.test_ctx_options.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_options
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_options
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_options
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_options:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ctx_options


PostBuild.test_dgram.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_dgram
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_dgram
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_dgram
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_dgram:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_dgram


PostBuild.test_diffserv.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_diffserv
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_diffserv
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_diffserv
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_diffserv:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_diffserv


PostBuild.test_disconnect_inproc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_disconnect_inproc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_disconnect_inproc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_disconnect_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_disconnect_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_disconnect_inproc


PostBuild.test_filter_ipc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_filter_ipc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_filter_ipc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_filter_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_filter_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_filter_ipc


PostBuild.test_fork.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_fork
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_fork
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_fork
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_fork:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_fork


PostBuild.test_getsockopt_memset.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_getsockopt_memset
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_getsockopt_memset
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_getsockopt_memset
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_getsockopt_memset:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_getsockopt_memset


PostBuild.test_heartbeats.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_heartbeats
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_heartbeats
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_heartbeats
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_heartbeats:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_heartbeats


PostBuild.test_hwm.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm


PostBuild.test_hwm_pubsub.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm_pubsub
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm_pubsub
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm_pubsub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm_pubsub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_hwm_pubsub


PostBuild.test_immediate.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_immediate
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_immediate
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_immediate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_immediate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_immediate


PostBuild.test_inproc_connect.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_inproc_connect
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_inproc_connect
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_inproc_connect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_inproc_connect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_inproc_connect


PostBuild.test_invalid_rep.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_invalid_rep
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_invalid_rep
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_invalid_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_invalid_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_invalid_rep


PostBuild.test_iov.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_iov
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_iov
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_iov
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_iov:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_iov


PostBuild.test_ipc_wildcard.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ipc_wildcard
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ipc_wildcard
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ipc_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ipc_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_ipc_wildcard


PostBuild.test_issue_566.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_issue_566
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_issue_566
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_issue_566
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_issue_566:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_issue_566


PostBuild.test_last_endpoint.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_last_endpoint
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_last_endpoint
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_last_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_last_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_last_endpoint


PostBuild.test_many_sockets.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_many_sockets
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_many_sockets
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_many_sockets
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_many_sockets:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_many_sockets


PostBuild.test_metadata.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_metadata
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_metadata
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_metadata
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_metadata:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_metadata


PostBuild.test_mock_pub_sub.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_mock_pub_sub
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_mock_pub_sub
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_mock_pub_sub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_mock_pub_sub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_mock_pub_sub


PostBuild.test_monitor.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_monitor
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_monitor
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_monitor
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_monitor:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_monitor


PostBuild.test_msg_ffn.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_ffn
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_ffn
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_ffn
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_ffn:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_ffn


PostBuild.test_msg_flags.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_flags
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_flags
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_flags
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_flags:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_msg_flags


PostBuild.test_pair_inproc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_inproc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_inproc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_inproc


PostBuild.test_pair_ipc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_ipc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_ipc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_ipc


PostBuild.test_pair_tcp.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_tcp
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_tcp
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pair_tcp


PostBuild.test_poller.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_poller
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_poller
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_poller
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_poller:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_poller


PostBuild.test_probe_router.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_probe_router
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_probe_router
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_probe_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_probe_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_probe_router


PostBuild.test_proxy.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy


PostBuild.test_proxy_hwm.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_hwm
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_hwm
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_hwm


PostBuild.test_proxy_single_socket.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_single_socket
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_single_socket
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_single_socket
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_single_socket:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_single_socket


PostBuild.test_proxy_terminate.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_terminate
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_terminate
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_terminate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_terminate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_proxy_terminate


PostBuild.test_pub_invert_matching.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pub_invert_matching
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pub_invert_matching
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pub_invert_matching
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pub_invert_matching:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_pub_invert_matching


PostBuild.test_radio_dish.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_radio_dish
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_radio_dish
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_radio_dish
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_radio_dish:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_radio_dish


PostBuild.test_rebind_ipc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_rebind_ipc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_rebind_ipc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_rebind_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_rebind_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_rebind_ipc


PostBuild.test_reconnect_ivl.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reconnect_ivl
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reconnect_ivl
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reconnect_ivl
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reconnect_ivl:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reconnect_ivl


PostBuild.test_req_correlate.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_correlate
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_correlate
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_correlate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_correlate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_correlate


PostBuild.test_req_relaxed.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_relaxed
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_relaxed
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_relaxed
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_relaxed:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_req_relaxed


PostBuild.test_reqrep_device.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_device
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_device
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_device
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_device:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_device


PostBuild.test_reqrep_inproc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_inproc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_inproc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_inproc


PostBuild.test_reqrep_ipc.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_ipc
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_ipc
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_ipc


PostBuild.test_reqrep_tcp.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_tcp
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_tcp
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_reqrep_tcp


PostBuild.test_router_handover.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_handover
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_handover
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_handover
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_handover:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_handover


PostBuild.test_router_mandatory.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory


PostBuild.test_router_mandatory_hwm.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory_hwm
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory_hwm
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_mandatory_hwm


PostBuild.test_router_notify.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_notify
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_notify
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_notify
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_notify:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_router_notify


PostBuild.test_scatter_gather.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_scatter_gather
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_scatter_gather
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_scatter_gather
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_scatter_gather:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_scatter_gather


PostBuild.test_security_curve.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_curve
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_curve
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_curve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_curve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_curve


PostBuild.test_security_gssapi.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_gssapi
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_gssapi
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_gssapi
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_gssapi:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_gssapi


PostBuild.test_security_no_zap_handler.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_no_zap_handler
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_no_zap_handler
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_no_zap_handler
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_no_zap_handler:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_no_zap_handler


PostBuild.test_security_null.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_null
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_null
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_null


PostBuild.test_security_plain.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_plain
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_plain
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_plain
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_plain:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_plain


PostBuild.test_security_zap.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_zap
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_zap
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_zap
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_zap:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_security_zap


PostBuild.test_setsockopt.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_setsockopt
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_setsockopt
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_setsockopt
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_setsockopt:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_setsockopt


PostBuild.test_shutdown_stress.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_shutdown_stress
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_shutdown_stress
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_shutdown_stress
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_shutdown_stress:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_shutdown_stress


PostBuild.test_socket_null.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_socket_null
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_socket_null
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_socket_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_socket_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_socket_null


PostBuild.test_sockopt_hwm.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sockopt_hwm
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sockopt_hwm
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sockopt_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sockopt_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sockopt_hwm


PostBuild.test_sodium.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sodium
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sodium
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sodium
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sodium:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sodium


PostBuild.test_spec_dealer.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_dealer
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_dealer
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_dealer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_dealer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_dealer


PostBuild.test_spec_pushpull.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_pushpull
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_pushpull
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_pushpull
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_pushpull:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_pushpull


PostBuild.test_spec_rep.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_rep
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_rep
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_rep


PostBuild.test_spec_req.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_req
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_req
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_req
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_req:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_req


PostBuild.test_spec_router.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_router
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_router
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_spec_router


PostBuild.test_srcfd.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_srcfd
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_srcfd
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_srcfd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_srcfd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_srcfd


PostBuild.test_stream.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream


PostBuild.test_stream_disconnect.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_disconnect
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_disconnect
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_disconnect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_disconnect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_disconnect


PostBuild.test_stream_empty.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_empty
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_empty
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_empty
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_empty:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_empty


PostBuild.test_stream_exceeds_buffer.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_exceeds_buffer
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_exceeds_buffer
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_exceeds_buffer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_exceeds_buffer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_exceeds_buffer


PostBuild.test_stream_timeout.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_timeout
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_timeout
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_timeout
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_timeout:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_stream_timeout


PostBuild.test_sub_forward.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sub_forward
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sub_forward
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sub_forward
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sub_forward:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_sub_forward


PostBuild.test_system.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_system
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_system
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_system
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_system:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_system


PostBuild.test_term_endpoint.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_term_endpoint
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_term_endpoint
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_term_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_term_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_term_endpoint


PostBuild.test_thread_safe.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_thread_safe
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_thread_safe
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_thread_safe
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_thread_safe:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_thread_safe


PostBuild.test_timeo.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timeo
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timeo
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timeo
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timeo:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timeo


PostBuild.test_timers.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timers
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timers
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timers
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timers:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_timers


PostBuild.test_unbind_wildcard.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_unbind_wildcard
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_unbind_wildcard
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_unbind_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_unbind_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_unbind_wildcard


PostBuild.test_use_fd.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_use_fd
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_use_fd
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_use_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_use_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_use_fd


PostBuild.test_xpub_manual.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual


PostBuild.test_xpub_manual_last_value.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual_last_value
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual_last_value
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual_last_value
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual_last_value:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_manual_last_value


PostBuild.test_xpub_nodrop.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_nodrop
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_nodrop
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_nodrop
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_nodrop:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_nodrop


PostBuild.test_xpub_verbose.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_verbose
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_verbose
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_verbose
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_verbose:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_verbose


PostBuild.test_xpub_welcome_msg.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_welcome_msg
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_welcome_msg
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_welcome_msg
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_welcome_msg:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_xpub_welcome_msg


PostBuild.test_zmq_poll_fd.Debug:
PostBuild.testutil.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_zmq_poll_fd
PostBuild.libzmq.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_zmq_poll_fd
PostBuild.unity.Debug: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_zmq_poll_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_zmq_poll_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Debug/test_zmq_poll_fd


PostBuild.testutil.Debug:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a


PostBuild.testutil-static.Debug:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil-static.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil-static.a


PostBuild.unity.Debug:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a


PostBuild.test_ancillaries.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ancillaries
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ancillaries
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ancillaries
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ancillaries:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ancillaries


PostBuild.test_app_meta.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_app_meta
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_app_meta
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_app_meta
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_app_meta:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_app_meta


PostBuild.test_atomics.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_atomics
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_atomics
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_atomics
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_atomics:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_atomics


PostBuild.test_base85.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_base85
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_base85
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_base85
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_base85:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_base85


PostBuild.test_bind_after_connect_tcp.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_after_connect_tcp
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_after_connect_tcp
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_after_connect_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_after_connect_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_after_connect_tcp


PostBuild.test_bind_src_address.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_src_address
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_src_address
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_src_address
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_src_address:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_bind_src_address


PostBuild.test_capabilities.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_capabilities
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_capabilities
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_capabilities
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_capabilities:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_capabilities


PostBuild.test_client_server.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_client_server
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_client_server
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_client_server
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_client_server:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_client_server


PostBuild.test_conflate.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_conflate
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_conflate
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_conflate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_conflate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_conflate


PostBuild.test_connect_resolve.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_resolve
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_resolve
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_resolve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_resolve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_resolve


PostBuild.test_connect_rid.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_rid
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_rid
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_rid
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_rid:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_connect_rid


PostBuild.test_ctx_destroy.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_destroy
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_destroy
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_destroy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_destroy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_destroy


PostBuild.test_ctx_options.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_options
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_options
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_options
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_options:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ctx_options


PostBuild.test_dgram.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_dgram
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_dgram
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_dgram
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_dgram:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_dgram


PostBuild.test_diffserv.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_diffserv
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_diffserv
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_diffserv
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_diffserv:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_diffserv


PostBuild.test_disconnect_inproc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_disconnect_inproc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_disconnect_inproc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_disconnect_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_disconnect_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_disconnect_inproc


PostBuild.test_filter_ipc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_filter_ipc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_filter_ipc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_filter_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_filter_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_filter_ipc


PostBuild.test_fork.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_fork
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_fork
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_fork
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_fork:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_fork


PostBuild.test_getsockopt_memset.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_getsockopt_memset
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_getsockopt_memset
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_getsockopt_memset
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_getsockopt_memset:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_getsockopt_memset


PostBuild.test_heartbeats.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_heartbeats
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_heartbeats
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_heartbeats
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_heartbeats:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_heartbeats


PostBuild.test_hwm.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm


PostBuild.test_hwm_pubsub.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm_pubsub
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm_pubsub
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm_pubsub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm_pubsub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_hwm_pubsub


PostBuild.test_immediate.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_immediate
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_immediate
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_immediate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_immediate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_immediate


PostBuild.test_inproc_connect.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_inproc_connect
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_inproc_connect
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_inproc_connect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_inproc_connect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_inproc_connect


PostBuild.test_invalid_rep.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_invalid_rep
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_invalid_rep
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_invalid_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_invalid_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_invalid_rep


PostBuild.test_iov.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_iov
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_iov
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_iov
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_iov:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_iov


PostBuild.test_ipc_wildcard.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ipc_wildcard
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ipc_wildcard
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ipc_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ipc_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_ipc_wildcard


PostBuild.test_issue_566.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_issue_566
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_issue_566
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_issue_566
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_issue_566:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_issue_566


PostBuild.test_last_endpoint.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_last_endpoint
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_last_endpoint
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_last_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_last_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_last_endpoint


PostBuild.test_many_sockets.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_many_sockets
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_many_sockets
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_many_sockets
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_many_sockets:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_many_sockets


PostBuild.test_metadata.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_metadata
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_metadata
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_metadata
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_metadata:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_metadata


PostBuild.test_mock_pub_sub.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_mock_pub_sub
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_mock_pub_sub
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_mock_pub_sub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_mock_pub_sub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_mock_pub_sub


PostBuild.test_monitor.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_monitor
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_monitor
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_monitor
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_monitor:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_monitor


PostBuild.test_msg_ffn.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_ffn
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_ffn
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_ffn
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_ffn:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_ffn


PostBuild.test_msg_flags.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_flags
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_flags
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_flags
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_flags:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_msg_flags


PostBuild.test_pair_inproc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_inproc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_inproc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_inproc


PostBuild.test_pair_ipc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_ipc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_ipc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_ipc


PostBuild.test_pair_tcp.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_tcp
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_tcp
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pair_tcp


PostBuild.test_poller.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_poller
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_poller
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_poller
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_poller:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_poller


PostBuild.test_probe_router.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_probe_router
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_probe_router
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_probe_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_probe_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_probe_router


PostBuild.test_proxy.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy


PostBuild.test_proxy_hwm.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_hwm
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_hwm
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_hwm


PostBuild.test_proxy_single_socket.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_single_socket
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_single_socket
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_single_socket
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_single_socket:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_single_socket


PostBuild.test_proxy_terminate.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_terminate
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_terminate
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_terminate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_terminate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_proxy_terminate


PostBuild.test_pub_invert_matching.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pub_invert_matching
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pub_invert_matching
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pub_invert_matching
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pub_invert_matching:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_pub_invert_matching


PostBuild.test_radio_dish.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_radio_dish
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_radio_dish
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_radio_dish
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_radio_dish:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_radio_dish


PostBuild.test_rebind_ipc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_rebind_ipc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_rebind_ipc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_rebind_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_rebind_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_rebind_ipc


PostBuild.test_reconnect_ivl.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reconnect_ivl
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reconnect_ivl
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reconnect_ivl
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reconnect_ivl:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reconnect_ivl


PostBuild.test_req_correlate.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_correlate
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_correlate
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_correlate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_correlate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_correlate


PostBuild.test_req_relaxed.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_relaxed
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_relaxed
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_relaxed
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_relaxed:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_req_relaxed


PostBuild.test_reqrep_device.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_device
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_device
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_device
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_device:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_device


PostBuild.test_reqrep_inproc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_inproc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_inproc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_inproc


PostBuild.test_reqrep_ipc.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_ipc
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_ipc
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_ipc


PostBuild.test_reqrep_tcp.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_tcp
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_tcp
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_reqrep_tcp


PostBuild.test_router_handover.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_handover
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_handover
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_handover
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_handover:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_handover


PostBuild.test_router_mandatory.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory


PostBuild.test_router_mandatory_hwm.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory_hwm
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory_hwm
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_mandatory_hwm


PostBuild.test_router_notify.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_notify
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_notify
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_notify
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_notify:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_router_notify


PostBuild.test_scatter_gather.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_scatter_gather
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_scatter_gather
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_scatter_gather
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_scatter_gather:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_scatter_gather


PostBuild.test_security_curve.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_curve
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_curve
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_curve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_curve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_curve


PostBuild.test_security_gssapi.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_gssapi
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_gssapi
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_gssapi
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_gssapi:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_gssapi


PostBuild.test_security_no_zap_handler.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_no_zap_handler
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_no_zap_handler
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_no_zap_handler
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_no_zap_handler:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_no_zap_handler


PostBuild.test_security_null.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_null
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_null
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_null


PostBuild.test_security_plain.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_plain
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_plain
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_plain
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_plain:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_plain


PostBuild.test_security_zap.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_zap
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_zap
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_zap
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_zap:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_security_zap


PostBuild.test_setsockopt.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_setsockopt
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_setsockopt
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_setsockopt
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_setsockopt:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_setsockopt


PostBuild.test_shutdown_stress.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_shutdown_stress
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_shutdown_stress
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_shutdown_stress
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_shutdown_stress:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_shutdown_stress


PostBuild.test_socket_null.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_socket_null
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_socket_null
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_socket_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_socket_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_socket_null


PostBuild.test_sockopt_hwm.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sockopt_hwm
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sockopt_hwm
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sockopt_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sockopt_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sockopt_hwm


PostBuild.test_sodium.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sodium
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sodium
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sodium
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sodium:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sodium


PostBuild.test_spec_dealer.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_dealer
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_dealer
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_dealer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_dealer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_dealer


PostBuild.test_spec_pushpull.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_pushpull
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_pushpull
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_pushpull
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_pushpull:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_pushpull


PostBuild.test_spec_rep.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_rep
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_rep
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_rep


PostBuild.test_spec_req.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_req
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_req
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_req
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_req:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_req


PostBuild.test_spec_router.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_router
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_router
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_spec_router


PostBuild.test_srcfd.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_srcfd
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_srcfd
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_srcfd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_srcfd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_srcfd


PostBuild.test_stream.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream


PostBuild.test_stream_disconnect.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_disconnect
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_disconnect
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_disconnect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_disconnect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_disconnect


PostBuild.test_stream_empty.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_empty
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_empty
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_empty
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_empty:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_empty


PostBuild.test_stream_exceeds_buffer.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_exceeds_buffer
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_exceeds_buffer
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_exceeds_buffer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_exceeds_buffer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_exceeds_buffer


PostBuild.test_stream_timeout.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_timeout
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_timeout
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_timeout
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_timeout:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_stream_timeout


PostBuild.test_sub_forward.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sub_forward
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sub_forward
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sub_forward
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sub_forward:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_sub_forward


PostBuild.test_system.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_system
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_system
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_system
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_system:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_system


PostBuild.test_term_endpoint.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_term_endpoint
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_term_endpoint
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_term_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_term_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_term_endpoint


PostBuild.test_thread_safe.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_thread_safe
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_thread_safe
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_thread_safe
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_thread_safe:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_thread_safe


PostBuild.test_timeo.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timeo
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timeo
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timeo
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timeo:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timeo


PostBuild.test_timers.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timers
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timers
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timers
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timers:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_timers


PostBuild.test_unbind_wildcard.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_unbind_wildcard
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_unbind_wildcard
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_unbind_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_unbind_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_unbind_wildcard


PostBuild.test_use_fd.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_use_fd
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_use_fd
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_use_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_use_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_use_fd


PostBuild.test_xpub_manual.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual


PostBuild.test_xpub_manual_last_value.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual_last_value
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual_last_value
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual_last_value
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual_last_value:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_manual_last_value


PostBuild.test_xpub_nodrop.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_nodrop
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_nodrop
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_nodrop
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_nodrop:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_nodrop


PostBuild.test_xpub_verbose.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_verbose
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_verbose
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_verbose
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_verbose:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_verbose


PostBuild.test_xpub_welcome_msg.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_welcome_msg
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_welcome_msg
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_welcome_msg
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_welcome_msg:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_xpub_welcome_msg


PostBuild.test_zmq_poll_fd.Release:
PostBuild.testutil.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_zmq_poll_fd
PostBuild.libzmq.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_zmq_poll_fd
PostBuild.unity.Release: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_zmq_poll_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_zmq_poll_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/Release/test_zmq_poll_fd


PostBuild.testutil.Release:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a


PostBuild.testutil-static.Release:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil-static.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil-static.a


PostBuild.unity.Release:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a


PostBuild.test_ancillaries.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ancillaries
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ancillaries
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ancillaries
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ancillaries:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ancillaries


PostBuild.test_app_meta.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_app_meta
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_app_meta
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_app_meta
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_app_meta:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_app_meta


PostBuild.test_atomics.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_atomics
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_atomics
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_atomics
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_atomics:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_atomics


PostBuild.test_base85.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_base85
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_base85
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_base85
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_base85:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_base85


PostBuild.test_bind_after_connect_tcp.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_after_connect_tcp
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_after_connect_tcp
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_after_connect_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_after_connect_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_after_connect_tcp


PostBuild.test_bind_src_address.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_src_address
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_src_address
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_src_address
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_src_address:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_bind_src_address


PostBuild.test_capabilities.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_capabilities
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_capabilities
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_capabilities
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_capabilities:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_capabilities


PostBuild.test_client_server.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_client_server
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_client_server
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_client_server
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_client_server:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_client_server


PostBuild.test_conflate.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_conflate
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_conflate
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_conflate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_conflate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_conflate


PostBuild.test_connect_resolve.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_resolve
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_resolve
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_resolve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_resolve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_resolve


PostBuild.test_connect_rid.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_rid
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_rid
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_rid
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_rid:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_connect_rid


PostBuild.test_ctx_destroy.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_destroy
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_destroy
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_destroy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_destroy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_destroy


PostBuild.test_ctx_options.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_options
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_options
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_options
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_options:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ctx_options


PostBuild.test_dgram.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_dgram
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_dgram
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_dgram
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_dgram:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_dgram


PostBuild.test_diffserv.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_diffserv
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_diffserv
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_diffserv
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_diffserv:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_diffserv


PostBuild.test_disconnect_inproc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_disconnect_inproc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_disconnect_inproc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_disconnect_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_disconnect_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_disconnect_inproc


PostBuild.test_filter_ipc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_filter_ipc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_filter_ipc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_filter_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_filter_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_filter_ipc


PostBuild.test_fork.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_fork
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_fork
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_fork
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_fork:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_fork


PostBuild.test_getsockopt_memset.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_getsockopt_memset
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_getsockopt_memset
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_getsockopt_memset
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_getsockopt_memset:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_getsockopt_memset


PostBuild.test_heartbeats.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_heartbeats
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_heartbeats
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_heartbeats
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_heartbeats:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_heartbeats


PostBuild.test_hwm.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm


PostBuild.test_hwm_pubsub.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm_pubsub
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm_pubsub
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm_pubsub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm_pubsub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_hwm_pubsub


PostBuild.test_immediate.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_immediate
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_immediate
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_immediate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_immediate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_immediate


PostBuild.test_inproc_connect.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_inproc_connect
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_inproc_connect
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_inproc_connect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_inproc_connect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_inproc_connect


PostBuild.test_invalid_rep.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_invalid_rep
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_invalid_rep
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_invalid_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_invalid_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_invalid_rep


PostBuild.test_iov.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_iov
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_iov
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_iov
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_iov:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_iov


PostBuild.test_ipc_wildcard.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ipc_wildcard
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ipc_wildcard
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ipc_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ipc_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_ipc_wildcard


PostBuild.test_issue_566.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_issue_566
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_issue_566
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_issue_566
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_issue_566:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_issue_566


PostBuild.test_last_endpoint.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_last_endpoint
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_last_endpoint
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_last_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_last_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_last_endpoint


PostBuild.test_many_sockets.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_many_sockets
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_many_sockets
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_many_sockets
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_many_sockets:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_many_sockets


PostBuild.test_metadata.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_metadata
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_metadata
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_metadata
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_metadata:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_metadata


PostBuild.test_mock_pub_sub.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_mock_pub_sub
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_mock_pub_sub
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_mock_pub_sub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_mock_pub_sub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_mock_pub_sub


PostBuild.test_monitor.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_monitor
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_monitor
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_monitor
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_monitor:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_monitor


PostBuild.test_msg_ffn.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_ffn
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_ffn
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_ffn
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_ffn:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_ffn


PostBuild.test_msg_flags.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_flags
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_flags
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_flags
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_flags:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_msg_flags


PostBuild.test_pair_inproc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_inproc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_inproc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_inproc


PostBuild.test_pair_ipc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_ipc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_ipc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_ipc


PostBuild.test_pair_tcp.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_tcp
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_tcp
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pair_tcp


PostBuild.test_poller.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_poller
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_poller
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_poller
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_poller:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_poller


PostBuild.test_probe_router.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_probe_router
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_probe_router
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_probe_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_probe_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_probe_router


PostBuild.test_proxy.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy


PostBuild.test_proxy_hwm.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_hwm
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_hwm
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_hwm


PostBuild.test_proxy_single_socket.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_single_socket
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_single_socket
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_single_socket
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_single_socket:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_single_socket


PostBuild.test_proxy_terminate.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_terminate
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_terminate
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_terminate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_terminate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_proxy_terminate


PostBuild.test_pub_invert_matching.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pub_invert_matching
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pub_invert_matching
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pub_invert_matching
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pub_invert_matching:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_pub_invert_matching


PostBuild.test_radio_dish.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_radio_dish
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_radio_dish
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_radio_dish
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_radio_dish:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_radio_dish


PostBuild.test_rebind_ipc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_rebind_ipc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_rebind_ipc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_rebind_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_rebind_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_rebind_ipc


PostBuild.test_reconnect_ivl.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reconnect_ivl
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reconnect_ivl
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reconnect_ivl
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reconnect_ivl:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reconnect_ivl


PostBuild.test_req_correlate.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_correlate
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_correlate
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_correlate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_correlate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_correlate


PostBuild.test_req_relaxed.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_relaxed
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_relaxed
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_relaxed
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_relaxed:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_req_relaxed


PostBuild.test_reqrep_device.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_device
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_device
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_device
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_device:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_device


PostBuild.test_reqrep_inproc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_inproc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_inproc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_inproc


PostBuild.test_reqrep_ipc.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_ipc
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_ipc
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_ipc


PostBuild.test_reqrep_tcp.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_tcp
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_tcp
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_reqrep_tcp


PostBuild.test_router_handover.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_handover
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_handover
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_handover
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_handover:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_handover


PostBuild.test_router_mandatory.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory


PostBuild.test_router_mandatory_hwm.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory_hwm
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory_hwm
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_mandatory_hwm


PostBuild.test_router_notify.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_notify
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_notify
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_notify
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_notify:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_router_notify


PostBuild.test_scatter_gather.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_scatter_gather
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_scatter_gather
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_scatter_gather
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_scatter_gather:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_scatter_gather


PostBuild.test_security_curve.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_curve
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_curve
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_curve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_curve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_curve


PostBuild.test_security_gssapi.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_gssapi
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_gssapi
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_gssapi
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_gssapi:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_gssapi


PostBuild.test_security_no_zap_handler.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_no_zap_handler
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_no_zap_handler
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_no_zap_handler
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_no_zap_handler:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_no_zap_handler


PostBuild.test_security_null.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_null
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_null
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_null


PostBuild.test_security_plain.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_plain
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_plain
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_plain
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_plain:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_plain


PostBuild.test_security_zap.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_zap
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_zap
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_zap
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_zap:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_security_zap


PostBuild.test_setsockopt.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_setsockopt
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_setsockopt
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_setsockopt
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_setsockopt:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_setsockopt


PostBuild.test_shutdown_stress.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_shutdown_stress
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_shutdown_stress
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_shutdown_stress
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_shutdown_stress:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_shutdown_stress


PostBuild.test_socket_null.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_socket_null
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_socket_null
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_socket_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_socket_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_socket_null


PostBuild.test_sockopt_hwm.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sockopt_hwm
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sockopt_hwm
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sockopt_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sockopt_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sockopt_hwm


PostBuild.test_sodium.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sodium
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sodium
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sodium
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sodium:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sodium


PostBuild.test_spec_dealer.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_dealer
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_dealer
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_dealer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_dealer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_dealer


PostBuild.test_spec_pushpull.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_pushpull
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_pushpull
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_pushpull
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_pushpull:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_pushpull


PostBuild.test_spec_rep.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_rep
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_rep
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_rep


PostBuild.test_spec_req.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_req
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_req
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_req
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_req:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_req


PostBuild.test_spec_router.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_router
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_router
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_spec_router


PostBuild.test_srcfd.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_srcfd
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_srcfd
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_srcfd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_srcfd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_srcfd


PostBuild.test_stream.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream


PostBuild.test_stream_disconnect.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_disconnect
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_disconnect
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_disconnect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_disconnect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_disconnect


PostBuild.test_stream_empty.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_empty
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_empty
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_empty
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_empty:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_empty


PostBuild.test_stream_exceeds_buffer.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_exceeds_buffer
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_exceeds_buffer
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_exceeds_buffer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_exceeds_buffer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_exceeds_buffer


PostBuild.test_stream_timeout.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_timeout
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_timeout
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_timeout
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_timeout:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_stream_timeout


PostBuild.test_sub_forward.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sub_forward
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sub_forward
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sub_forward
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sub_forward:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_sub_forward


PostBuild.test_system.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_system
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_system
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_system
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_system:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_system


PostBuild.test_term_endpoint.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_term_endpoint
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_term_endpoint
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_term_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_term_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_term_endpoint


PostBuild.test_thread_safe.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_thread_safe
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_thread_safe
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_thread_safe
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_thread_safe:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_thread_safe


PostBuild.test_timeo.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timeo
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timeo
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timeo
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timeo:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timeo


PostBuild.test_timers.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timers
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timers
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timers
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timers:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_timers


PostBuild.test_unbind_wildcard.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_unbind_wildcard
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_unbind_wildcard
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_unbind_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_unbind_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_unbind_wildcard


PostBuild.test_use_fd.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_use_fd
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_use_fd
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_use_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_use_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_use_fd


PostBuild.test_xpub_manual.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual


PostBuild.test_xpub_manual_last_value.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual_last_value
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual_last_value
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual_last_value
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual_last_value:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_manual_last_value


PostBuild.test_xpub_nodrop.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_nodrop
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_nodrop
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_nodrop
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_nodrop:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_nodrop


PostBuild.test_xpub_verbose.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_verbose
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_verbose
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_verbose
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_verbose:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_verbose


PostBuild.test_xpub_welcome_msg.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_welcome_msg
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_welcome_msg
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_welcome_msg
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_welcome_msg:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_xpub_welcome_msg


PostBuild.test_zmq_poll_fd.MinSizeRel:
PostBuild.testutil.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_zmq_poll_fd
PostBuild.libzmq.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_zmq_poll_fd
PostBuild.unity.MinSizeRel: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_zmq_poll_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_zmq_poll_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/MinSizeRel/test_zmq_poll_fd


PostBuild.testutil.MinSizeRel:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a


PostBuild.testutil-static.MinSizeRel:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil-static.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil-static.a


PostBuild.unity.MinSizeRel:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a


PostBuild.test_ancillaries.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ancillaries
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ancillaries
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ancillaries
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ancillaries:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ancillaries


PostBuild.test_app_meta.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_app_meta
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_app_meta
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_app_meta
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_app_meta:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_app_meta


PostBuild.test_atomics.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_atomics
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_atomics
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_atomics
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_atomics:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_atomics


PostBuild.test_base85.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_base85
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_base85
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_base85
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_base85:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_base85


PostBuild.test_bind_after_connect_tcp.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_after_connect_tcp
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_after_connect_tcp
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_after_connect_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_after_connect_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_after_connect_tcp


PostBuild.test_bind_src_address.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_src_address
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_src_address
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_src_address
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_src_address:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_bind_src_address


PostBuild.test_capabilities.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_capabilities
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_capabilities
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_capabilities
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_capabilities:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_capabilities


PostBuild.test_client_server.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_client_server
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_client_server
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_client_server
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_client_server:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_client_server


PostBuild.test_conflate.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_conflate
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_conflate
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_conflate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_conflate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_conflate


PostBuild.test_connect_resolve.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_resolve
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_resolve
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_resolve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_resolve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_resolve


PostBuild.test_connect_rid.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_rid
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_rid
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_rid
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_rid:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_connect_rid


PostBuild.test_ctx_destroy.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_destroy
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_destroy
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_destroy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_destroy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_destroy


PostBuild.test_ctx_options.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_options
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_options
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_options
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_options:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ctx_options


PostBuild.test_dgram.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_dgram
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_dgram
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_dgram
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_dgram:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_dgram


PostBuild.test_diffserv.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_diffserv
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_diffserv
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_diffserv
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_diffserv:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_diffserv


PostBuild.test_disconnect_inproc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_disconnect_inproc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_disconnect_inproc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_disconnect_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_disconnect_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_disconnect_inproc


PostBuild.test_filter_ipc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_filter_ipc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_filter_ipc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_filter_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_filter_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_filter_ipc


PostBuild.test_fork.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_fork
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_fork
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_fork
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_fork:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_fork


PostBuild.test_getsockopt_memset.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_getsockopt_memset
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_getsockopt_memset
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_getsockopt_memset
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_getsockopt_memset:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_getsockopt_memset


PostBuild.test_heartbeats.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_heartbeats
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_heartbeats
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_heartbeats
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_heartbeats:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_heartbeats


PostBuild.test_hwm.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm


PostBuild.test_hwm_pubsub.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm_pubsub
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm_pubsub
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm_pubsub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm_pubsub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_hwm_pubsub


PostBuild.test_immediate.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_immediate
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_immediate
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_immediate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_immediate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_immediate


PostBuild.test_inproc_connect.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_inproc_connect
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_inproc_connect
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_inproc_connect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_inproc_connect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_inproc_connect


PostBuild.test_invalid_rep.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_invalid_rep
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_invalid_rep
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_invalid_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_invalid_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_invalid_rep


PostBuild.test_iov.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_iov
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_iov
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_iov
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_iov:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_iov


PostBuild.test_ipc_wildcard.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ipc_wildcard
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ipc_wildcard
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ipc_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ipc_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_ipc_wildcard


PostBuild.test_issue_566.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_issue_566
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_issue_566
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_issue_566
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_issue_566:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_issue_566


PostBuild.test_last_endpoint.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_last_endpoint
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_last_endpoint
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_last_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_last_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_last_endpoint


PostBuild.test_many_sockets.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_many_sockets
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_many_sockets
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_many_sockets
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_many_sockets:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_many_sockets


PostBuild.test_metadata.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_metadata
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_metadata
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_metadata
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_metadata:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_metadata


PostBuild.test_mock_pub_sub.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_mock_pub_sub
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_mock_pub_sub
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_mock_pub_sub
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_mock_pub_sub:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_mock_pub_sub


PostBuild.test_monitor.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_monitor
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_monitor
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_monitor
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_monitor:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_monitor


PostBuild.test_msg_ffn.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_ffn
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_ffn
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_ffn
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_ffn:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_ffn


PostBuild.test_msg_flags.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_flags
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_flags
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_flags
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_flags:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_msg_flags


PostBuild.test_pair_inproc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_inproc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_inproc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_inproc


PostBuild.test_pair_ipc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_ipc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_ipc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_ipc


PostBuild.test_pair_tcp.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_tcp
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_tcp
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pair_tcp


PostBuild.test_poller.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_poller
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_poller
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_poller
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_poller:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_poller


PostBuild.test_probe_router.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_probe_router
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_probe_router
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_probe_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_probe_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_probe_router


PostBuild.test_proxy.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy


PostBuild.test_proxy_hwm.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_hwm
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_hwm
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_hwm


PostBuild.test_proxy_single_socket.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_single_socket
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_single_socket
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_single_socket
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_single_socket:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_single_socket


PostBuild.test_proxy_terminate.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_terminate
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_terminate
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_terminate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_terminate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_proxy_terminate


PostBuild.test_pub_invert_matching.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pub_invert_matching
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pub_invert_matching
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pub_invert_matching
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pub_invert_matching:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_pub_invert_matching


PostBuild.test_radio_dish.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_radio_dish
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_radio_dish
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_radio_dish
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_radio_dish:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_radio_dish


PostBuild.test_rebind_ipc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_rebind_ipc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_rebind_ipc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_rebind_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_rebind_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_rebind_ipc


PostBuild.test_reconnect_ivl.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reconnect_ivl
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reconnect_ivl
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reconnect_ivl
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reconnect_ivl:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reconnect_ivl


PostBuild.test_req_correlate.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_correlate
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_correlate
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_correlate
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_correlate:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_correlate


PostBuild.test_req_relaxed.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_relaxed
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_relaxed
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_relaxed
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_relaxed:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_req_relaxed


PostBuild.test_reqrep_device.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_device
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_device
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_device
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_device:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_device


PostBuild.test_reqrep_inproc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_inproc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_inproc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_inproc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_inproc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_inproc


PostBuild.test_reqrep_ipc.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_ipc
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_ipc
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_ipc
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_ipc:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_ipc


PostBuild.test_reqrep_tcp.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_tcp
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_tcp
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_tcp
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_tcp:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_reqrep_tcp


PostBuild.test_router_handover.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_handover
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_handover
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_handover
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_handover:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_handover


PostBuild.test_router_mandatory.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory


PostBuild.test_router_mandatory_hwm.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory_hwm
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory_hwm
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_mandatory_hwm


PostBuild.test_router_notify.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_notify
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_notify
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_notify
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_notify:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_router_notify


PostBuild.test_scatter_gather.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_scatter_gather
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_scatter_gather
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_scatter_gather
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_scatter_gather:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_scatter_gather


PostBuild.test_security_curve.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_curve
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_curve
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_curve
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_curve:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_curve


PostBuild.test_security_gssapi.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_gssapi
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_gssapi
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_gssapi
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_gssapi:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_gssapi


PostBuild.test_security_no_zap_handler.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_no_zap_handler
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_no_zap_handler
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_no_zap_handler
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_no_zap_handler:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_no_zap_handler


PostBuild.test_security_null.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_null
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_null
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_null


PostBuild.test_security_plain.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_plain
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_plain
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_plain
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_plain:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_plain


PostBuild.test_security_zap.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_zap
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_zap
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_zap
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_zap:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_security_zap


PostBuild.test_setsockopt.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_setsockopt
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_setsockopt
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_setsockopt
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_setsockopt:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_setsockopt


PostBuild.test_shutdown_stress.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_shutdown_stress
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_shutdown_stress
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_shutdown_stress
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_shutdown_stress:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_shutdown_stress


PostBuild.test_socket_null.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_socket_null
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_socket_null
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_socket_null
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_socket_null:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_socket_null


PostBuild.test_sockopt_hwm.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sockopt_hwm
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sockopt_hwm
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sockopt_hwm
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sockopt_hwm:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sockopt_hwm


PostBuild.test_sodium.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sodium
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sodium
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sodium
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sodium:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sodium


PostBuild.test_spec_dealer.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_dealer
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_dealer
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_dealer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_dealer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_dealer


PostBuild.test_spec_pushpull.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_pushpull
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_pushpull
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_pushpull
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_pushpull:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_pushpull


PostBuild.test_spec_rep.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_rep
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_rep
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_rep
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_rep:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_rep


PostBuild.test_spec_req.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_req
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_req
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_req
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_req:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_req


PostBuild.test_spec_router.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_router
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_router
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_router
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_router:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_spec_router


PostBuild.test_srcfd.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_srcfd
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_srcfd
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_srcfd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_srcfd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_srcfd


PostBuild.test_stream.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream


PostBuild.test_stream_disconnect.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_disconnect
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_disconnect
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_disconnect
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_disconnect:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_disconnect


PostBuild.test_stream_empty.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_empty
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_empty
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_empty
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_empty:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_empty


PostBuild.test_stream_exceeds_buffer.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_exceeds_buffer
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_exceeds_buffer
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_exceeds_buffer
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_exceeds_buffer:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_exceeds_buffer


PostBuild.test_stream_timeout.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_timeout
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_timeout
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_timeout
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_timeout:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_stream_timeout


PostBuild.test_sub_forward.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sub_forward
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sub_forward
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sub_forward
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sub_forward:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_sub_forward


PostBuild.test_system.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_system
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_system
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_system
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_system:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_system


PostBuild.test_term_endpoint.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_term_endpoint
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_term_endpoint
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_term_endpoint
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_term_endpoint:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_term_endpoint


PostBuild.test_thread_safe.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_thread_safe
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_thread_safe
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_thread_safe
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_thread_safe:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_thread_safe


PostBuild.test_timeo.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timeo
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timeo
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timeo
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timeo:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timeo


PostBuild.test_timers.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timers
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timers
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timers
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timers:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_timers


PostBuild.test_unbind_wildcard.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_unbind_wildcard
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_unbind_wildcard
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_unbind_wildcard
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_unbind_wildcard:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_unbind_wildcard


PostBuild.test_use_fd.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_use_fd
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_use_fd
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_use_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_use_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_use_fd


PostBuild.test_xpub_manual.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual


PostBuild.test_xpub_manual_last_value.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual_last_value
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual_last_value
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual_last_value
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual_last_value:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_manual_last_value


PostBuild.test_xpub_nodrop.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_nodrop
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_nodrop
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_nodrop
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_nodrop:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_nodrop


PostBuild.test_xpub_verbose.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_verbose
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_verbose
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_verbose
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_verbose:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_verbose


PostBuild.test_xpub_welcome_msg.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_welcome_msg
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_welcome_msg
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_welcome_msg
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_welcome_msg:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_xpub_welcome_msg


PostBuild.test_zmq_poll_fd.RelWithDebInfo:
PostBuild.testutil.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_zmq_poll_fd
PostBuild.libzmq.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_zmq_poll_fd
PostBuild.unity.RelWithDebInfo: /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_zmq_poll_fd
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_zmq_poll_fd:\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib\
	/usr/local/lib/libsodium.dylib\
	/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/bin/RelWithDebInfo/test_zmq_poll_fd


PostBuild.testutil.RelWithDebInfo:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a


PostBuild.testutil-static.RelWithDebInfo:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil-static.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil-static.a


PostBuild.unity.RelWithDebInfo:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a:
	/bin/rm -f /Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a




# For each target create a dummy ruleso the target does not have to exist
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libtestutil.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libunity.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Debug/libzmq.5.2.3.dylib:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libtestutil.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libunity.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/MinSizeRel/libzmq.5.2.3.dylib:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libtestutil.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libunity.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/RelWithDebInfo/libzmq.5.2.3.dylib:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libtestutil.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libunity.a:
/Users/steph/Documents/CloudStation/ingescape/code/libzmq/builds/xcode/lib/Release/libzmq.5.2.3.dylib:
/usr/local/lib/libsodium.dylib:
