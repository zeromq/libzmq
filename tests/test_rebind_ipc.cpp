/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

static const char *SOCKET_ADDR = "ipc:///tmp/test_rebind_ipc";


int main (void)
{
    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb0 = zmq_socket (ctx, ZMQ_PUSH);
    assert (sb0);
    void *sb1 = zmq_socket (ctx, ZMQ_PUSH);
    assert (sb1);

    int rc = zmq_bind (sb0, SOCKET_ADDR);
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_PULL);
    assert (sc);
    rc = zmq_connect (sc, SOCKET_ADDR);
    assert (rc == 0);

    rc = zmq_send (sb0, "42", 2, 0);
    assert (rc == 2);

    char buffer[2];
    rc = zmq_recv (sc, buffer, 2, 0);
    assert (rc == 2);

    rc = zmq_close (sb0);
    assert (rc == 0);

    rc = zmq_bind (sb1, SOCKET_ADDR);
    assert (rc == 0);

    rc = zmq_send (sb1, "42", 2, 0);
    assert (rc == 2);

    rc = zmq_recv (sc, buffer, 2, 0);
    assert (rc == 2);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb1);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
