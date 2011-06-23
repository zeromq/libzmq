/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include "stddef.h"
#include "stdint.hpp"
#include "blob.hpp"

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

        uint64_t affinity;
        blob_t identity;

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

        //  If 1, (X)SUB socket should filter the messages. If 0, it should not.
        int filter;

        // The timeout for send/recv operations for this socket.
        int rcvtimeo;
        int sndtimeo;

        //  If true, when connecting, pipes are created immediately without
        //  waiting for the connection to be established. That way the socket
        //  is not aware of the peer's identity, however, it is able to send
        //  messages straight away.
        bool immediate_connect;

        //  If true, session reads all the pending messages from the pipe and
        //  sends them to the network when socket is closed.
        bool delay_on_close;

        //  If true, socket reads all the messages from the pipe and delivers
        //  them to the user when the peer terminates.
        bool delay_on_disconnect;
    };

}

#endif
