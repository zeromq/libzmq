/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <limits>
#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    int rc;
    
    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    assert (zmq_ctx_get (ctx, ZMQ_MAX_SOCKETS) == ZMQ_MAX_SOCKETS_DFLT);
#if defined(ZMQ_USE_SELECT)
    assert (zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT) == FD_SETSIZE - 1);
#elif    defined(ZMQ_USE_POLL) || defined(ZMQ_USE_EPOLL)     \
      || defined(ZMQ_USE_DEVPOLL) || defined(ZMQ_USE_KQUEUE)
    assert (zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT) == 65535);
#endif
    assert (zmq_ctx_get (ctx, ZMQ_IO_THREADS) == ZMQ_IO_THREADS_DFLT);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 0);
#if defined (ZMQ_BUILD_DRAFT_AP)
    assert (zmq_ctx_get (ctx, ZMQ_MSG_T_SIZE) == sizeof (zmq_msg_t));
#endif
    
    rc = zmq_ctx_set (ctx, ZMQ_IPV6, true);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 1);
    
    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    int value;
    size_t optsize = sizeof (int);
    rc = zmq_getsockopt (router, ZMQ_IPV6, &value, &optsize);
    assert (rc == 0);
    assert (value == 1);
    rc = zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize);
    assert (rc == 0);
    assert (value == -1);
    rc = zmq_close (router);
    assert (rc == 0);
    
    rc = zmq_ctx_set (ctx, ZMQ_BLOCKY, false);
    assert (zmq_ctx_get (ctx, ZMQ_BLOCKY) == 0);
    router = zmq_socket (ctx, ZMQ_ROUTER);
    rc = zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize);
    assert (rc == 0);
    assert (value == 0);
    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
