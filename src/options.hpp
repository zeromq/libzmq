/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_OPTIONS_HPP_INCLUDED__
#define __ZMQ_OPTIONS_HPP_INCLUDED__

#include <string>
#include <vector>

#include "stddef.h"
#include "stdint.hpp"
#include "tcp_address.hpp"
#include "../include/zmq.h"

namespace zmq
{

    struct options_t
    {
        options_t ();

        int setsockopt (int option_, const void *optval_, size_t optvallen_);
        int getsockopt (int option_, void *optval_, size_t *optvallen_);

        //  High-water marks for message pipes.
        int sndhwm;
        int rcvhwm;

        //  I/O thread affinity.
        uint64_t affinity;

        //  Socket identity
        unsigned char identity_size;
        unsigned char identity [256];

        // Last socket endpoint resolved URI
        std::string last_endpoint;

        //  Maximum tranfer rate [kb/s]. Default 100kb/s.
        int rate;

        //  Reliability time interval [ms]. Default 10 seconds.
        int recovery_ivl;

        // Sets the time-to-live field in every multicast packet sent.
        int multicast_hops;

        // SO_SNDBUF and SO_RCVBUF to be passed to underlying transport sockets.
        int sndbuf;
        int rcvbuf;

        //  Socket type.
        int type;

        //  Linger time, in milliseconds.
        int linger;

        //  Minimum interval between attempts to reconnect, in milliseconds.
        //  Default 100ms
        int reconnect_ivl;

        //  Maximum interval between attempts to reconnect, in milliseconds.
        //  Default 0 (unused)
        int reconnect_ivl_max;

        //  Maximum backlog for pending connections.
        int backlog;

        //  Maximal size of message to handle.
        int64_t maxmsgsize;

        // The timeout for send/recv operations for this socket.
        int rcvtimeo;
        int sndtimeo;

        //  If 1, indicates the use of IPv4 sockets only, it will not be
        //  possible to communicate with IPv6-only hosts. If 0, the socket can
        //  connect to and accept connections from both IPv4 and IPv6 hosts.
        int ipv4only;
        
        //  If 1, connecting pipes are not attached immediately, meaning a send()
        //  on a socket with only connecting pipes would block
        int delay_attach_on_connect;

        //  If true, session reads all the pending messages from the pipe and
        //  sends them to the network when socket is closed.
        bool delay_on_close;

        //  If true, socket reads all the messages from the pipe and delivers
        //  them to the user when the peer terminates.
        bool delay_on_disconnect;

        //  If 1, (X)SUB socket should filter the messages. If 0, it should not.
        bool filter;

        //  If true, the identity message is forwarded to the socket.
        bool recv_identity;

        //  TCP keep-alive settings.
        //  Defaults to -1 = do not change socket options
        int tcp_keepalive;
        int tcp_keepalive_cnt;
        int tcp_keepalive_idle;
        int tcp_keepalive_intvl;

        // TCP accept() filters
        typedef std::vector <tcp_address_mask_t> tcp_accept_filters_t;
        tcp_accept_filters_t tcp_accept_filters;

        //  ID of the socket.
        int socket_id;
    };

}

#endif
