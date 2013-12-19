/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

int main (int argc, char *argv [])
{
    const char *bind_1 = "tcp://127.0.0.1:5555/resource/1";
    const char *bind_2 = "tcp://127.0.0.1:5555/resource/2";

    int rc;

    void* ctx = zmq_init (1);
    assert (ctx);

    void* p1 = zmq_socket (ctx, ZMQ_PUSH);
    assert (p1);

    rc = zmq_bind(p1, bind_1);
    assert (rc == 0);

    void* p2 = zmq_socket (ctx, ZMQ_PUSH);
    assert (p2);
    
    // should be able to bind a second socket to the same ip/port
    // but with different resource
    rc = zmq_bind(p2, bind_2);
    assert (rc == 0);

    rc = zmq_close (p1);
    assert (rc == 0);

    rc = zmq_close (p2);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
