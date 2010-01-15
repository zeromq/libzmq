dist_man_MANS = man1/zmq_forwarder.1 man1/zmq_streamer.1 man1/zmq_queue.1 \
    man3/zmq_init.3 man3/zmq_term.3 \
    man3/zmq_socket.3 man3/zmq_close.3 man3/zmq_setsockopt.3 man3/zmq_bind.3 \
    man3/zmq_connect.3 man3/zmq_send.3 man3/zmq_flush.3 man3/zmq_recv.3 \
    man3/zmq_poll.3 man3/zmq_msg_init.3 man3/zmq_msg_init_size.3 \
    man3/zmq_msg_close.3 man3/zmq_msg_move.3 man3/zmq_msg_copy.3 \
    man3/zmq_msg_data.3 man3/zmq_msg_size.3 man3/zmq_strerror.3 \
    man7/zmq.7 man7/zmq_cpp.7 man7/zmq_python.7 man7/zmq_ruby.7 \
    man7/zmq_cl.7 man7/zmq_tcp.7 man7/zmq_udp.7 man7/zmq_pgm.7 \
    man7/zmq_inproc.7 man7/zmq_ipc.7

distclean-local:
		-rm  *.pdf
		-rm  man1/*.ps
		-rm  man3/*.ps
		-rm  man7/*.ps

dist-hook:
		./convert2pdf.sh
		$(mkdir_p) $(top_distdir)/doc
		cp $(top_srcdir)/man/*.pdf $(top_distdir)/doc

