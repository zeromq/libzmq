#!/bin/sh
#
# Copyright (c) 2007-2009 FastMQ Inc.
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

groff -man -Tps man1/zmq_forwarder.1 > man1/zmq_forwarder.1.ps
ps2pdf man1/zmq_forwarder.1.ps zmq_forwarder.pdf

groff -man -Tps man3/zmq_init.3 > man3/zmq_init.3.ps
ps2pdf man3/zmq_init.3.ps zmq_init.pdf
groff -man -Tps man3/zmq_term.3 > man3/zmq_term.3.ps
ps2pdf man3/zmq_term.3.ps zmq_term.pdf
groff -man -Tps man3/zmq_socket.3 > man3/zmq_socket.3.ps
ps2pdf man3/zmq_socket.3.ps zmq_socket.pdf
groff -man -Tps man3/zmq_close.3 > man3/zmq_close.3.ps
ps2pdf man3/zmq_close.3.ps zmq_close.pdf
groff -man -Tps man3/zmq_setsockopt.3 > man3/zmq_setsockopt.3.ps
ps2pdf man3/zmq_setsockopt.3.ps zmq_setsockopt.pdf
groff -man -Tps man3/zmq_bind.3 > man3/zmq_bind.3.ps
ps2pdf man3/zmq_bind.3.ps zmq_bind.pdf
groff -man -Tps man3/zmq_connect.3 > man3/zmq_connect.3.ps
ps2pdf man3/zmq_connect.3.ps zmq_connect.pdf
groff -man -Tps man3/zmq_send.3 > man3/zmq_send.3.ps
ps2pdf man3/zmq_send.3.ps zmq_send.pdf
groff -man -Tps man3/zmq_flush.3 > man3/zmq_flush.3.ps
ps2pdf man3/zmq_flush.3.ps zmq_flush.pdf
groff -man -Tps man3/zmq_recv.3 > man3/zmq_recv.3.ps
ps2pdf man3/zmq_recv.3.ps zmq_recv.pdf
groff -man -Tps man3/zmq_poll.3 > man3/zmq_poll.3.ps
ps2pdf man3/zmq_poll.3.ps zmq_poll.pdf
groff -man -Tps man3/zmq_msg_init.3 > man3/zmq_msg_init.3.ps
ps2pdf man3/zmq_msg_init.3.ps zmq_msg_init.pdf
groff -man -Tps man3/zmq_msg_init_size.3 > man3/zmq_msg_init_size.3.ps
ps2pdf man3/zmq_msg_init_size.3.ps zmq_msg_init_size.pdf
groff -man -Tps man3/zmq_msg_init_data.3 > man3/zmq_msg_init_data.3.ps
ps2pdf man3/zmq_msg_init_data.3.ps zmq_msg_init_data.pdf
groff -man -Tps man3/zmq_msg_close.3 > man3/zmq_msg_close.3.ps
ps2pdf man3/zmq_msg_close.3.ps zmq_msg_close.pdf
groff -man -Tps man3/zmq_msg_move.3 > man3/zmq_msg_move.3.ps
ps2pdf man3/zmq_msg_move.3.ps zmq_msg_move.pdf
groff -man -Tps man3/zmq_msg_copy.3 > man3/zmq_msg_copy.3.ps
ps2pdf man3/zmq_msg_copy.3.ps zmq_msg_copy.pdf
groff -man -Tps man3/zmq_msg_data.3 > man3/zmq_msg_data.3.ps
ps2pdf man3/zmq_msg_data.3.ps zmq_msg_data.pdf
groff -man -Tps man3/zmq_msg_size.3 > man3/zmq_msg_size.3.ps
ps2pdf man3/zmq_msg_size.3.ps zmq_msg_size.pdf
groff -man -Tps man3/zmq_strerror.3 > man3/zmq_strerror.3.ps
ps2pdf man3/zmq_strerror.3.ps zmq_strerror.pdf

groff -man -Tps man7/zmq.7 > man7/zmq.7.ps
ps2pdf man7/zmq.7.ps zmq.pdf

