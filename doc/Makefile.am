MAN3 = zmq_bind.3 zmq_unbind.3 zmq_connect.3 zmq_disconnect.3 zmq_close.3 \
    zmq_ctx_new.3 zmq_ctx_term.3 zmq_ctx_destroy.3 zmq_ctx_get.3 zmq_ctx_set.3 \
    zmq_msg_init.3 zmq_msg_init_data.3 zmq_msg_init_size.3 \
    zmq_msg_move.3 zmq_msg_copy.3 zmq_msg_size.3 zmq_msg_data.3 zmq_msg_close.3 \
    zmq_msg_send.3 zmq_msg_recv.3 \
    zmq_send.3 zmq_recv.3 zmq_send_const.3 \
    zmq_msg_get.3 zmq_msg_set.3 zmq_msg_more.3 \
    zmq_getsockopt.3 zmq_setsockopt.3 \
    zmq_socket.3 zmq_socket_monitor.3 zmq_poll.3 \
    zmq_errno.3 zmq_strerror.3 zmq_version.3 zmq_proxy.3 zmq_proxy_steerable.3 \
    zmq_sendmsg.3 zmq_recvmsg.3 zmq_init.3 zmq_term.3 \
    zmq_z85_encode.3 zmq_z85_decode.3 zmq_curve_keypair.3

MAN7 = zmq.7 zmq_tcp.7 zmq_pgm.7 zmq_epgm.7 zmq_inproc.7 zmq_ipc.7 \
    zmq_null.7 zmq_plain.7 zmq_curve.7

MAN_DOC = $(MAN1) $(MAN3) $(MAN7)

MAN_TXT = $(MAN3:%.3=%.txt)
MAN_TXT += $(MAN7:%.7=%.txt)
MAN_HTML = $(MAN_TXT:%.txt=%.html)

if INSTALL_MAN
dist_man_MANS = $(MAN_DOC)
endif

EXTRA_DIST = asciidoc.conf $(MAN_TXT)
if BUILD_DOC
EXTRA_DIST += $(MAN_HTML)
endif

MAINTAINERCLEANFILES = $(MAN_DOC) $(MAN_HTML)

dist-hook : $(MAN_DOC) $(MAN_HTML)

if BUILD_DOC
SUFFIXES=.html .txt .xml .3 .7

.txt.html:
	asciidoc -d manpage -b xhtml11 -f $(srcdir)/asciidoc.conf \
		-azmq_version=@PACKAGE_VERSION@ -o$@ $<
.txt.xml:
	asciidoc -d manpage -b docbook -f $(srcdir)/asciidoc.conf \
		-azmq_version=@PACKAGE_VERSION@ -o$@ $<
.xml.1:
	xmlto man $<
.xml.3:
	xmlto man $<
.xml.7:
	xmlto man $<
zmq_epgm.7: zmq_pgm.7
	cp zmq_pgm.7 $@
endif
