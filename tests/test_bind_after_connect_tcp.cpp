/*
    Copyright (c) 2016 Contributors as noted in the AUTHORS file

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
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_DEALER);
    assert (sb);

    void *sc = zmq_socket (ctx, ZMQ_DEALER);
    assert (sc);

    int rc = zmq_connect (sc, ENDPOINT_3);
    assert (rc == 0);

    rc = zmq_send_const (sc, "foobar", 6, 0);
    assert (rc == 6);

    rc = zmq_send_const (sc, "baz", 3, 0);
    assert (rc == 3);

    rc = zmq_send_const (sc, "buzz", 4, 0);
    assert (rc == 4);

    rc = zmq_bind (sb, ENDPOINT_3);
    assert (rc == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 6);
    void *data = zmq_msg_data (&msg);
    assert (memcmp ("foobar", data, 6) == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 3);
    data = zmq_msg_data (&msg);
    assert (memcmp ("baz", data, 3) == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);
    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 4);
    data = zmq_msg_data (&msg);
    assert (memcmp ("buzz", data, 4) == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
