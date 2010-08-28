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

#include <assert.h>
#include <string>

#include "testutil.hpp"

using namespace std;
using namespace zmqtestutil;

int main ()
{
    zmq::context_t context (1);

    zmq::pollitem_t items [2];
    socket_pair p = create_bound_pair (&context, ZMQ_PAIR, ZMQ_PAIR,
        "tcp://127.0.0.1:2000");

    //  First test simple ping pong.
    const string expect ("XXX");

    {
        const string returned = zmqtestutil::ping_pong (p, expect);
        assert (expect == returned);

        //  Adjust socket state so that poll shows only 1 pending message.
        zmq::message_t mx ;
        p.first->recv (&mx, 0);
    }

    {
        zmq::message_t m1 (expect.size ());
        memcpy (m1.data (), expect.c_str (), expect.size ());
        items [0].socket = *p.first;
        items [0].fd = 0;
        items [0].events = ZMQ_POLLIN;
        items [0].revents = 0;
        items [1].socket = *p.second;
        items [1].fd = 0;
        items [1].events = ZMQ_POLLIN;
        items [1].revents = 0;

        p.first->send (m1, 0);

        int rc = zmq::poll (&items [0], 2, -1);
        assert (rc == 1);
        assert ((items [1].revents & ZMQ_POLLIN) != 0);

        zmq::message_t m2;
        p.second->recv (&m2, 0);
        const string ret ((char*) m2.data (), m2.size ());
        assert (expect == ret);
    }

    //  Delete sockets.
    delete (p.first);
    delete (p.second);

    return 0 ;
assert (false);
}
