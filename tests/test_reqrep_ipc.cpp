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

void test_leak (void)
{
    char my_endpoint[256];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_bind (sb, "ipc://*");
    assert (rc == 0);
    size_t len = sizeof(my_endpoint);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, my_endpoint);
    assert (rc == 0);

    rc = s_send (sc, "leakymsg");
    assert (rc == strlen ("leakymsg"));

    char *buf = s_recv (sb);
    free (buf);

    rc = zmq_close (sc);
    assert (rc == 0);

    msleep (SETTLE_TIME);

    rc = s_send (sb, "leakymsg");
    assert (rc == strlen ("leakymsg"));

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_simple (void)
{
    char my_endpoint[256];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_bind (sb, "ipc://*");
    assert (rc == 0);
    size_t len = sizeof(my_endpoint);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, my_endpoint);
    assert (rc == 0);
    
    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();

    test_simple ();

    test_leak ();

    return 0 ;
}
