#
# documentation
#
MAN3 = \
    zmq_bind.3 zmq_unbind.3 zmq_connect.3 zmq_connect_peer.3 zmq_disconnect.3 zmq_close.3 \
    zmq_ctx_new.3 zmq_ctx_term.3 zmq_ctx_get.3 zmq_ctx_set.3 zmq_ctx_shutdown.3 \
    zmq_msg_init.3 zmq_msg_init_data.3 zmq_msg_init_size.3 zmq_msg_init_buffer.3 \
    zmq_msg_move.3 zmq_msg_copy.3 zmq_msg_size.3 zmq_msg_data.3 zmq_msg_close.3 \
    zmq_msg_send.3 zmq_msg_recv.3 \
    zmq_msg_routing_id.3 zmq_msg_set_routing_id.3 \
    zmq_send.3 zmq_recv.3 zmq_send_const.3 \
    zmq_msg_get.3 zmq_msg_set.3 zmq_msg_more.3 zmq_msg_gets.3 \
    zmq_getsockopt.3 zmq_setsockopt.3 \
    zmq_socket.3 zmq_socket_monitor.3 zmq_poll.3 zmq_ppoll.3 \
    zmq_socket_monitor_versioned.3 \
    zmq_errno.3 zmq_strerror.3 zmq_version.3 \
    zmq_sendmsg.3 zmq_recvmsg.3 \
    zmq_proxy.3 zmq_proxy_steerable.3 \
    zmq_z85_encode.3 zmq_z85_decode.3 zmq_curve_keypair.3 zmq_curve_public.3 \
    zmq_has.3 \
    zmq_timers.3 zmq_poller.3 \
    zmq_atomic_counter_new.3 zmq_atomic_counter_set.3 \
    zmq_atomic_counter_inc.3 zmq_atomic_counter_dec.3 \
    zmq_atomic_counter_value.3 zmq_atomic_counter_destroy.3

MAN7 = \
    zmq.7 zmq_tcp.7 zmq_pgm.7 zmq_inproc.7 zmq_ipc.7 \
    zmq_null.7 zmq_plain.7 zmq_curve.7 zmq_tipc.7 zmq_vmci.7 zmq_udp.7 \
    zmq_gssapi.7

# MAN_ADOC contains all original Asciidoc files from git repo
MAN_ADOC = $(MAN3:%.3=%.adoc) $(MAN7:%.7=%.adoc)

# MAN_DOC contains all the MANUAL PAGES (generated from asciidoc files)
MAN_DOC = $(MAN3) $(MAN7) 

# MAN_HTML contains all the HTML PAGES (generated from asciidoc files)
MAN_HTML = $(MAN_ADOC:%.adoc=%.html)

MAINTAINERCLEANFILES =
EXTRA_DIST = $(MAN_ADOC)


#
# BUILD_DOC is set when Asciidoctor has been found
# Declare here all the rules to produce documentation from .adoc files
#
if BUILD_DOC

EXTRA_DIST += $(MAN_HTML) $(MAN_DOC)
MAINTAINERCLEANFILES += $(MAN_HTML) $(MAN_DOC)
SUFFIXES=.html .adoc .3 .7

.adoc.html: 
	asciidoctor -b html -azmq_version=@PACKAGE_VERSION@  $<
.adoc.3:
	asciidoctor -b manpage -azmq_version=@PACKAGE_VERSION@  $<
.adoc.7:
	asciidoctor -b manpage -azmq_version=@PACKAGE_VERSION@  $<

dist-hook : $(MAN_DOC) $(MAN_HTML)

# To help publishing HTML files into github Pages, we indicate github that the "zmq.html" page is the index page;
# that page contains a link to all other documentation pages
all-local : $(MAN_DOC) $(MAN_HTML)
	ln -sf zmq.html index.html

clean-local :
	rm -f $(MAN3) $(MAN7) $(MAN_HTML)

endif



#
# INSTALL_MAN is set when BUILD_DOC was set and additionally the manpages need to be installed
#
if INSTALL_MAN
dist_man_MANS = $(MAN_DOC)
endif
