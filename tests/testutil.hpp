/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_TEST_TESTUTIL_HPP_INCLUDED__
#define __ZMQ_TEST_TESTUTIL_HPP_INCLUDED__

#include "../include/zmq.hpp"

#include <utility>

namespace zmqtestutil
{

    typedef std::pair <zmq::socket_t*, zmq::socket_t*> socket_pair;

    socket_pair create_bound_pair (zmq::context_t *context_,
        int t1_, int t2_, const char *transport_)
    {
        zmq::socket_t *s1 = new zmq::socket_t (*context_, t1_);
        zmq::socket_t *s2 = new zmq::socket_t (*context_, t2_);
        s1->bind (transport_);
        s2->connect (transport_);
        return socket_pair (s1, s2);
    }

    std::string ping_pong (const socket_pair &sp_, const std::string &orig_msg_)
    {
        zmq::socket_t &s1 = *sp_.first;
        zmq::socket_t &s2 = *sp_.second;

        //  Construct message to send.
        zmq::message_t ping (orig_msg_.size ());
        memcpy (ping.data (), orig_msg_.c_str (), orig_msg_.size ());

        //  Send ping out.
        s1.send (ping, 0);

        //  Get pong from connected socket.
        zmq::message_t pong;
        s2.recv (&pong, 0);

        //  Return received data as std::string.
        return std::string ((char*) pong.data(), pong.size());
    }

}

#endif
