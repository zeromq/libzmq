#!/bin/sh
#
# Copyright (c) 2007-2010 iMatix Corporation
#
# This file is part of 0MQ.
#
# 0MQ is free software; you can redistribute it and/or modify it under
# the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# 0MQ is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# Lesser GNU General Public License for more details.
#
# You should have received a copy of the Lesser GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

groff -man -Thtml man1/zmq_forwarder.1 > man1/zmq_forwarder.1.html
groff -man -Thtml man1/zmq_streamer.1 > man1/zmq_streamer.1.html
groff -man -Thtml man1/zmq_queue.1 > man1/zmq_queue.1.html

groff -man -Thtml man3/zmq_init.3 > man3/zmq_init.3.html
groff -man -Thtml man3/zmq_term.3 > man3/zmq_term.3.html
groff -man -Thtml man3/zmq_socket.3 > man3/zmq_socket.3.html
groff -man -Thtml man3/zmq_close.3 > man3/zmq_close.3.html
groff -man -Thtml man3/zmq_setsockopt.3 > man3/zmq_setsockopt.3.html
groff -man -Thtml man3/zmq_bind.3 > man3/zmq_bind.3.html
groff -man -Thtml man3/zmq_connect.3 > man3/zmq_connect.3.html
groff -man -Thtml man3/zmq_send.3 > man3/zmq_send.3.html
groff -man -Thtml man3/zmq_flush.3 > man3/zmq_flush.3.html
groff -man -Thtml man3/zmq_recv.3 > man3/zmq_recv.3.html
groff -man -Thtml man3/zmq_poll.3 > man3/zmq_poll.3.html
groff -man -Thtml man3/zmq_msg_init.3 > man3/zmq_msg_init.3.html
groff -man -Thtml man3/zmq_msg_init_size.3 > man3/zmq_msg_init_size.3.html
groff -man -Thtml man3/zmq_msg_init_data.3 > man3/zmq_msg_init_data.3.html
groff -man -Thtml man3/zmq_msg_close.3 > man3/zmq_msg_close.3.html
groff -man -Thtml man3/zmq_msg_move.3 > man3/zmq_msg_move.3.html
groff -man -Thtml man3/zmq_msg_copy.3 > man3/zmq_msg_copy.3.html
groff -man -Thtml man3/zmq_msg_data.3 > man3/zmq_msg_data.3.html
groff -man -Thtml man3/zmq_msg_size.3 > man3/zmq_msg_size.3.html
groff -man -Thtml man3/zmq_strerror.3 > man3/zmq_strerror.3.html

groff -man -Thtml man7/zmq.7 > man7/zmq.7.html
groff -man -Thtml man7/zmq_cpp.7 > man7/zmq_cpp.7.html
groff -man -Thtml man7/zmq_python.7 > man7/zmq_python.7.html
groff -man -Thtml man7/zmq_ruby.7 > man7/zmq_ruby.7.html
groff -man -Thtml man7/zmq_cl.7 > man7/zmq_cl.7.html
groff -man -Thtml man7/zmq_tcp.7 > man7/zmq_tcp.7.html
groff -man -Thtml man7/zmq_udp.7 > man7/zmq_udp.7.html
groff -man -Thtml man7/zmq_pgm.7 > man7/zmq_pgm.7.html
groff -man -Thtml man7/zmq_inproc.7 > man7/zmq_inproc.7.html

