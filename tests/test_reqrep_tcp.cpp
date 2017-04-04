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

#include "testutil.hpp"

void test_single_connect_ipv4 (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_bind (sb, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    
    bounce (sb, sc);

    rc = zmq_disconnect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multi_connect_ipv4 (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int rc = zmq_bind (sb0, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_bind (sb1, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    void *sb2 = zmq_socket (ctx, ZMQ_REP);
    assert (sb2);
    rc = zmq_bind (sb2, "tcp://127.0.0.1:5562");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5561");
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5564;127.0.0.1:5562");
    assert (rc == 0);

    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);

    rc = zmq_disconnect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc, "tcp://127.0.0.1:5564;127.0.0.1:5562");
    assert (rc == 0);
    rc = zmq_disconnect (sc, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb0, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb1, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb2, "tcp://127.0.0.1:5562");
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb0);
    assert (rc == 0);

    rc = zmq_close (sb1);
    assert (rc == 0);

    rc = zmq_close (sb2);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multi_connect_ipv4_same_port (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int rc = zmq_bind (sb0, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_bind (sb1, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    void *sc0 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc0);
    rc = zmq_connect (sc0, "tcp://127.0.0.1:5564;127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_connect (sc0, "tcp://127.0.0.1:5565;127.0.0.1:5561");
    assert (rc == 0);

    void *sc1 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc1);
    rc = zmq_connect (sc1, "tcp://127.0.0.1:5565;127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_connect (sc1, "tcp://127.0.0.1:5564;127.0.0.1:5561");
    assert (rc == 0);

    bounce (sb0, sc0);
    bounce (sb1, sc0);
    bounce (sb0, sc1);
    bounce (sb1, sc1);
    bounce (sb0, sc0);
    bounce (sb1, sc0);

    rc = zmq_disconnect (sc1, "tcp://127.0.0.1:5565;127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc1, "tcp://127.0.0.1:5564;127.0.0.1:5561");
    assert (rc == 0);
    rc = zmq_disconnect (sc0, "tcp://127.0.0.1:5564;127.0.0.1:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc0, "tcp://127.0.0.1:5565;127.0.0.1:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb0, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb1, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    rc = zmq_close (sc0);
    assert (rc == 0);

    rc = zmq_close (sc1);
    assert (rc == 0);

    rc = zmq_close (sb0);
    assert (rc == 0);

    rc = zmq_close (sb1);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_single_connect_ipv6 (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    if (!is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int ipv6 = 1;
    int rc = zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb, "tcp://[::1]:5560");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://[::1]:5560");
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, "tcp://[::1]:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb, "tcp://[::1]:5560");
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multi_connect_ipv6 (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    if (!is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int ipv6 = 1;
    int rc = zmq_setsockopt (sb0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb0, "tcp://[::1]:5560");
    assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_setsockopt (sb1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb1, "tcp://[::1]:5561");
    assert (rc == 0);

    void *sb2 = zmq_socket (ctx, ZMQ_REP);
    assert (sb2);
    rc = zmq_setsockopt (sb2, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb2, "tcp://[::1]:5562");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://[::1]:5560");
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://[::1]:5561");
    assert (rc == 0);
    rc = zmq_connect (sc, "tcp://[::1]:5564;[::1]:5562");
    assert (rc == 0);

    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);

    rc = zmq_disconnect (sc, "tcp://[::1]:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc, "tcp://[::1]:5564;[::1]:5562");
    assert (rc == 0);
    rc = zmq_disconnect (sc, "tcp://[::1]:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb0, "tcp://[::1]:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb1, "tcp://[::1]:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb2, "tcp://[::1]:5562");
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb0);
    assert (rc == 0);

    rc = zmq_close (sb1);
    assert (rc == 0);

    rc = zmq_close (sb2);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multi_connect_ipv6_same_port (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    if (!is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int ipv6 = 1;
    int rc = zmq_setsockopt (sb0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb0, "tcp://[::1]:5560");
    assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_setsockopt (sb1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb1, "tcp://[::1]:5561");
    assert (rc == 0);

    void *sc0 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc0);
    rc = zmq_setsockopt (sc0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc0, "tcp://[::1]:5564;[::1]:5560");
    assert (rc == 0);
    rc = zmq_connect (sc0, "tcp://[::1]:5565;[::1]:5561");
    assert (rc == 0);

    void *sc1 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc1);
    rc = zmq_setsockopt (sc1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc1, "tcp://[::1]:5565;[::1]:5560");
    assert (rc == 0);
    rc = zmq_connect (sc1, "tcp://[::1]:5564;[::1]:5561");
    assert (rc == 0);

    bounce (sb0, sc0);
    bounce (sb1, sc0);
    bounce (sb0, sc1);
    bounce (sb1, sc1);
    bounce (sb0, sc0);
    bounce (sb1, sc0);

    rc = zmq_disconnect (sc1, "tcp://[::1]:5565;[::1]:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc1, "tcp://[::1]:5564;[::1]:5561");
    assert (rc == 0);
    rc = zmq_disconnect (sc0, "tcp://[::1]:5564;[::1]:5560");
    assert (rc == 0);
    rc = zmq_disconnect (sc0, "tcp://[::1]:5565;[::1]:5561");
    assert (rc == 0);

    rc = zmq_unbind (sb0, "tcp://[::1]:5560");
    assert (rc == 0);

    rc = zmq_unbind (sb1, "tcp://[::1]:5561");
    assert (rc == 0);

    rc = zmq_close (sc0);
    assert (rc == 0);

    rc = zmq_close (sc1);
    assert (rc == 0);

    rc = zmq_close (sb0);
    assert (rc == 0);

    rc = zmq_close (sb1);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment ();

    test_single_connect_ipv4 ();

    test_multi_connect_ipv4 ();

    test_multi_connect_ipv4_same_port ();

    test_single_connect_ipv6 ();

    test_multi_connect_ipv6 ();

    test_multi_connect_ipv6_same_port ();

    return 0 ;
}
