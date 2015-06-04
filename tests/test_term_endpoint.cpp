/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

int main (void)
{
    setup_test_environment();
    int rc;
    const size_t buf_size = 32;
    char buf[buf_size];
    const char *ep = "tcp://127.0.0.1:5560";
    const char *ep_wc_tcp = "tcp://127.0.0.1:*";
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    const char *ep_wc_ipc = "ipc://*";
#endif

    //  Create infrastructure.
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_bind (push, ep);
    assert (rc == 0);
    void *pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_connect (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    //  Unbind the listening endpoint
    rc = zmq_unbind (push, ep);
    assert (rc == 0);

    //  Allow unbind to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no outbound connection)
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Create infrastructure
    ctx = zmq_ctx_new ();
    assert (ctx);
    push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_connect (push, ep);
    assert (rc == 0);
    pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_bind (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established.
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    //  Disconnect the bound endpoint
    rc = zmq_disconnect (push, ep);
    assert (rc == 0);

    //  Allow disconnect to settle
    msleep (SETTLE_TIME);

    //  Check that sending would block (there's no inbound connections).
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up.
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Create infrastructure (wild-card binding)
    ctx = zmq_ctx_new ();
    assert (ctx);
    push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_bind (push, ep_wc_tcp);
    assert (rc == 0);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_bind (pull, ep_wc_ipc);
    assert (rc == 0);
#endif

    // Unbind sockets binded by wild-card address
    rc = zmq_getsockopt (push, ZMQ_LAST_ENDPOINT, buf, (size_t *)&buf_size);
    assert (rc == 0);
    rc = zmq_unbind (push, buf);
    assert (rc == 0);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    rc = zmq_getsockopt (pull, ZMQ_LAST_ENDPOINT, buf, (size_t *)&buf_size);
    assert (rc == 0);
    rc = zmq_unbind (pull, buf);
    assert (rc == 0);
#endif

    //  Create infrastructure (wild-card binding)
    ctx = zmq_ctx_new ();
    assert (ctx);
    push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_bind (push, ep_wc_tcp);
    assert (rc == 0);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_bind (pull, ep_wc_ipc);
    assert (rc == 0);
#endif

    // Sockets binded by wild-card address can't be unbinded by wild-card address
    rc = zmq_unbind (push, ep_wc_tcp);
    assert (rc == -1 && zmq_errno () == ENOENT);
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    rc = zmq_unbind (pull, ep_wc_ipc);
    assert (rc == -1 && zmq_errno () == ENOENT);
#endif

    return 0;
}
