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

void test_single_connect (const char *address)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    int ipv6;
    if (streq(address, "tcp://127.0.0.1:*"))
        ipv6 = 0;
    else if (streq(address, "tcp://[::1]:*"))
        ipv6 = 1;
    else
        assert (false);

    if (ipv6 && !is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb, address);
    assert (rc == 0);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc, my_endpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, my_endpoint);
    assert (rc == 0);

    rc = zmq_unbind (sb, my_endpoint);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_multi_connect (const char *address)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_0[MAX_SOCKET_STRING];
    char my_endpoint_1[MAX_SOCKET_STRING];
    char my_endpoint_2[MAX_SOCKET_STRING];
    char my_endpoint_3[MAX_SOCKET_STRING * 2];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    int ipv6;
    if (streq(address, "tcp://127.0.0.1:*"))
        ipv6 = 0;
    else if (streq(address, "tcp://[::1]:*"))
        ipv6 = 1;
    else
        assert (false);

    if (ipv6 && !is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int rc = zmq_setsockopt (sb0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb0, address);
    assert (rc == 0);
    rc = zmq_getsockopt (sb0, ZMQ_LAST_ENDPOINT, my_endpoint_0, &len);
     assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_setsockopt (sb1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb1, address);
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (sb1, ZMQ_LAST_ENDPOINT, my_endpoint_1, &len);
     assert (rc == 0);

    void *sb2 = zmq_socket (ctx, ZMQ_REP);
    assert (sb2);
    rc = zmq_setsockopt (sb2, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb2, address);
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (sb2, ZMQ_LAST_ENDPOINT, my_endpoint_2, &len);
     assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_connect (sc, my_endpoint_0);
    assert (rc == 0);
    rc = zmq_connect (sc, my_endpoint_1);
    assert (rc == 0);
    if (!ipv6)
        sprintf (my_endpoint_3, "tcp://127.0.0.1:5564;%s",
                strrchr(my_endpoint_2, '/') + 1);
    else
        sprintf (my_endpoint_3, "tcp://[::1]:5564;%s",
                strrchr(my_endpoint_2, '/') + 1);
    rc = zmq_connect (sc, my_endpoint_3);
    assert (rc == 0);

    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);
    bounce (sb1, sc);
    bounce (sb2, sc);
    bounce (sb0, sc);

    rc = zmq_disconnect (sc, my_endpoint_0);
    assert (rc == 0);
    rc = zmq_disconnect (sc, my_endpoint_3);
    assert (rc == 0);
    rc = zmq_disconnect (sc, my_endpoint_1);
    assert (rc == 0);

    rc = zmq_unbind (sb0, my_endpoint_0);
    assert (rc == 0);

    rc = zmq_unbind (sb1, my_endpoint_1);
    assert (rc == 0);

    rc = zmq_unbind (sb2, my_endpoint_2);
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

void test_multi_connect_same_port (const char *address)
{
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint_0[MAX_SOCKET_STRING];
    char my_endpoint_1[MAX_SOCKET_STRING];
    char my_endpoint_2[MAX_SOCKET_STRING * 2];
    char my_endpoint_3[MAX_SOCKET_STRING * 2];
    char my_endpoint_4[MAX_SOCKET_STRING * 2];
    char my_endpoint_5[MAX_SOCKET_STRING * 2];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    int ipv6;
    if (streq(address, "tcp://127.0.0.1:*"))
        ipv6 = 0;
    else if (streq(address, "tcp://[::1]:*"))
        ipv6 = 1;
    else
        assert (false);

    if (ipv6 && !is_ipv6_available ()) {
        zmq_ctx_term (ctx);
        return;
    }

    void *sb0 = zmq_socket (ctx, ZMQ_REP);
    assert (sb0);
    int rc = zmq_setsockopt (sb0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb0, address);
    assert (rc == 0);
    rc = zmq_getsockopt (sb0, ZMQ_LAST_ENDPOINT, my_endpoint_0, &len);
     assert (rc == 0);

    void *sb1 = zmq_socket (ctx, ZMQ_REP);
    assert (sb1);
    rc = zmq_setsockopt (sb1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_bind (sb1, address);
    assert (rc == 0);
    len = MAX_SOCKET_STRING;
    rc = zmq_getsockopt (sb1, ZMQ_LAST_ENDPOINT, my_endpoint_1, &len);
     assert (rc == 0);

    void *sc0 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc0);
    rc = zmq_setsockopt (sc0, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    if (!ipv6)
        sprintf (my_endpoint_2, "tcp://127.0.0.1:5564;%s",
                strrchr(my_endpoint_0, '/') + 1);
    else
        sprintf (my_endpoint_2, "tcp://[::1]:5564;%s",
                strrchr(my_endpoint_0, '/') + 1);
    rc = zmq_connect (sc0, my_endpoint_2);
    assert (rc == 0);
    if (!ipv6)
        sprintf (my_endpoint_3, "tcp://127.0.0.1:5565;%s",
                strrchr(my_endpoint_1, '/') + 1);
    else
        sprintf (my_endpoint_3, "tcp://[::1]:5565;%s",
                strrchr(my_endpoint_1, '/') + 1);
    rc = zmq_connect (sc0, my_endpoint_3);
    assert (rc == 0);

    void *sc1 = zmq_socket (ctx, ZMQ_REQ);
    assert (sc1);
    rc = zmq_setsockopt (sc1, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    if (!ipv6)
        sprintf (my_endpoint_4, "tcp://127.0.0.1:5565;%s",
                strrchr(my_endpoint_0, '/') + 1);
    else
        sprintf (my_endpoint_4, "tcp://[::1]:5565;%s",
                strrchr(my_endpoint_0, '/') + 1);
    rc = zmq_connect (sc1, my_endpoint_4);
    assert (rc == 0);
    if (!ipv6)
        sprintf (my_endpoint_5, "tcp://127.0.0.1:5564;%s",
                strrchr(my_endpoint_1, '/') + 1);
    else
        sprintf (my_endpoint_5, "tcp://[::1]:5564;%s",
                strrchr(my_endpoint_1, '/') + 1);
    rc = zmq_connect (sc1, my_endpoint_5);
    assert (rc == 0);

    bounce (sb0, sc0);
    bounce (sb1, sc0);
    bounce (sb0, sc1);
    bounce (sb1, sc1);
    bounce (sb0, sc0);
    bounce (sb1, sc0);

    rc = zmq_disconnect (sc1, my_endpoint_4);
    assert (rc == 0);
    rc = zmq_disconnect (sc1, my_endpoint_5);
    assert (rc == 0);
    rc = zmq_disconnect (sc0, my_endpoint_2);
    assert (rc == 0);
    rc = zmq_disconnect (sc0, my_endpoint_3);
    assert (rc == 0);

    rc = zmq_unbind (sb0, my_endpoint_0);
    assert (rc == 0);

    rc = zmq_unbind (sb1, my_endpoint_1);
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

    test_single_connect ("tcp://127.0.0.1:*");

    test_multi_connect ("tcp://127.0.0.1:*");

    test_multi_connect_same_port ("tcp://127.0.0.1:*");

    test_single_connect ("tcp://[::1]:*");

    test_multi_connect ("tcp://[::1]:*");

    test_multi_connect_same_port ("tcp://[::1]:*");

    return 0 ;
}
