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

const int MAX_SENDS = 10000;

enum TestType { BIND_FIRST, CONNECT_FIRST };

int test_defaults ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    // Set up bind socket
    void *bind_socket = zmq_socket (ctx, ZMQ_PULL);
    assert (bind_socket);
    rc = zmq_bind (bind_socket, "inproc://a");
    assert (rc == 0);

    // Set up connect socket
    void *connect_socket = zmq_socket (ctx, ZMQ_PUSH);
    assert (connect_socket);
    rc = zmq_connect (connect_socket, "inproc://a");
    assert (rc == 0);

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    assert (send_count == recv_count);

    // Clean up
    rc = zmq_close (connect_socket);
    assert (rc == 0);

    rc = zmq_close (bind_socket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return send_count;
}

int count_msg (int send_hwm, int recv_hwm, TestType testType)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    void *bind_socket;
    void *connect_socket;
    if (testType == BIND_FIRST)
    {
        // Set up bind socket
        bind_socket = zmq_socket (ctx, ZMQ_PULL);
        assert (bind_socket);
        rc = zmq_setsockopt (bind_socket, ZMQ_RCVHWM, &recv_hwm, sizeof (recv_hwm));
        assert (rc == 0);
        rc = zmq_bind (bind_socket, "inproc://a");
        assert (rc == 0);

        // Set up connect socket
        connect_socket = zmq_socket (ctx, ZMQ_PUSH);
        assert (connect_socket);
        rc = zmq_setsockopt (connect_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
        assert (rc == 0);
        rc = zmq_connect (connect_socket, "inproc://a");
        assert (rc == 0);
    }
    else
    {
        // Set up connect socket
        connect_socket = zmq_socket (ctx, ZMQ_PUSH);
        assert (connect_socket);
        rc = zmq_setsockopt (connect_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
        assert (rc == 0);
        rc = zmq_connect (connect_socket, "inproc://a");
        assert (rc == 0);

        // Set up bind socket
        bind_socket = zmq_socket (ctx, ZMQ_PULL);
        assert (bind_socket);
        rc = zmq_setsockopt (bind_socket, ZMQ_RCVHWM, &recv_hwm, sizeof (recv_hwm));
        assert (rc == 0);
        rc = zmq_bind (bind_socket, "inproc://a");
        assert (rc == 0);
    }

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    assert (send_count == recv_count);

    // Now it should be possible to send one more.
    rc = zmq_send (connect_socket, NULL, 0, 0);
    assert (rc == 0);

    //  Consume the remaining message.
    rc = zmq_recv (bind_socket, NULL, 0, 0);
    assert (rc == 0);

    // Clean up
    rc = zmq_close (connect_socket);
    assert (rc == 0);

    rc = zmq_close (bind_socket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return send_count;
}

int test_inproc_bind_first (int send_hwm, int recv_hwm)
{
    return count_msg(send_hwm, recv_hwm, BIND_FIRST);
}

int test_inproc_connect_first (int send_hwm, int recv_hwm)
{
    return count_msg(send_hwm, recv_hwm, CONNECT_FIRST);
}

int test_inproc_connect_and_close_first (int send_hwm, int recv_hwm)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    // Set up connect socket
    void *connect_socket = zmq_socket (ctx, ZMQ_PUSH);
    assert (connect_socket);
    rc = zmq_setsockopt (connect_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
    assert (rc == 0);
    rc = zmq_connect (connect_socket, "inproc://a");
    assert (rc == 0);

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Close connect
    rc = zmq_close (connect_socket);
    assert (rc == 0);

    // Set up bind socket
    void *bind_socket = zmq_socket (ctx, ZMQ_PULL);
    assert (bind_socket);
    rc = zmq_setsockopt (bind_socket, ZMQ_RCVHWM, &recv_hwm, sizeof (recv_hwm));
    assert (rc == 0);
    rc = zmq_bind (bind_socket, "inproc://a");
    assert (rc == 0);

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    assert (send_count == recv_count);

    // Clean up
    rc = zmq_close (bind_socket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return send_count;
}

int test_inproc_bind_and_close_first (int send_hwm, int /* recv_hwm */)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    // Set up bind socket
    void *bind_socket = zmq_socket (ctx, ZMQ_PUSH);
    assert (bind_socket);
    rc = zmq_setsockopt (bind_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
    assert (rc == 0);
    rc = zmq_bind (bind_socket, "inproc://a");
    assert (rc == 0);

    // Send until we block
    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send (bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Close bind
    rc = zmq_close (bind_socket);
    assert (rc == 0);

    /* Can't currently do connect without then wiring up a bind as things hang, this needs top be fixed.
    // Set up connect socket
    void *connect_socket = zmq_socket (ctx, ZMQ_PULL);
    assert (connect_socket);
    rc = zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &recv_hwm, sizeof (recv_hwm));
    assert (rc == 0);
    rc = zmq_connect (connect_socket, "inproc://a");
    assert (rc == 0);

    // Now receive all sent messages
    int recv_count = 0;
    while (zmq_recv (connect_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++recv_count;

    assert (send_count == recv_count);
    */

    // Clean up
    //rc = zmq_close (connect_socket);
    //assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return send_count;
}

int main (void)
{
    setup_test_environment();

    int count;

    // Default values are 1000 on send and 1000 one receive, so 2000 total
    count = test_defaults ();
    assert (count == 2000);

    // Infinite send and receive buffer
    count = test_inproc_bind_first (0, 0);
    assert (count == MAX_SENDS);
    count = test_inproc_connect_first (0, 0);
    assert (count == MAX_SENDS);

    // Infinite send buffer
    count = test_inproc_bind_first (1, 0);
    assert (count == MAX_SENDS);
    count = test_inproc_connect_first (1, 0);
    assert (count == MAX_SENDS);

    // Infinite receive buffer
    count = test_inproc_bind_first (0, 1);
    assert (count == MAX_SENDS);
    count = test_inproc_connect_first (0, 1);
    assert (count == MAX_SENDS);

    // Send and recv buffers hwm 1, so total that can be queued is 2
    count = test_inproc_bind_first (1, 1);
    assert (count == 2);
    count = test_inproc_connect_first (1, 1);
    assert (count == 2);

    // Send hwm of 1, send before bind so total that can be queued is 1
    count = test_inproc_connect_and_close_first (1, 0);
    assert (count == 1);

    // Send hwm of 1, send from bind side before connect so total that can be queued should be 1,
    // however currently all messages get thrown away before the connect.  BUG?
    count = test_inproc_bind_and_close_first (1, 0);
    //assert (count == 1);

    return 0;
}
