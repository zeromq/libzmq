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

int main (void)
{
    setup_test_environment();
    int rc;
    
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    assert (zmq_ctx_get (ctx, ZMQ_MAX_SOCKETS) == ZMQ_MAX_SOCKETS_DFLT);
    assert (zmq_ctx_get (ctx, ZMQ_IO_THREADS) == ZMQ_IO_THREADS_DFLT);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 0);
    
    rc = zmq_ctx_set (ctx, ZMQ_IPV6, true);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 1);
    
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    int ipv6;
    size_t optsize = sizeof (int);
    rc = zmq_getsockopt (router, ZMQ_IPV6, &ipv6, &optsize);
    assert (rc == 0);
    assert (ipv6);

    rc = zmq_close (router);
    assert (rc == 0);
    
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
