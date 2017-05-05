/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int ipv6 = is_ipv6_available ();

    /* Address wildcard, IPv6 disabled */
    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);

    int rc = zmq_bind (sb, "tcp://*:*");
    assert (rc == 0);

    char bindEndpoint[256];
    char connectEndpoint[256];
    size_t endpoint_len = sizeof (bindEndpoint);    
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, bindEndpoint, &endpoint_len);
    assert (rc == 0);

    //  Apparently Windows can't connect to 0.0.0.0. A better fix would be welcome.
#ifdef ZMQ_HAVE_WINDOWS
    sprintf (connectEndpoint, "tcp://127.0.0.1:%s",
                    strrchr(bindEndpoint, ':') + 1);
#else
    strcpy (connectEndpoint, bindEndpoint);
#endif

    rc = zmq_connect (sc, connectEndpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, connectEndpoint);
    assert (rc == 0);
    rc = zmq_unbind (sb, bindEndpoint);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);

    /* Address wildcard, IPv6 enabled */
    sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);

    rc = zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);

    rc = zmq_bind (sb, "tcp://*:*");
    assert (rc == 0);

    endpoint_len = sizeof (bindEndpoint);
    memset(bindEndpoint, 0, endpoint_len);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, bindEndpoint, &endpoint_len);
    assert (rc == 0);

#ifdef ZMQ_HAVE_WINDOWS
    if (ipv6)
        sprintf (connectEndpoint, "tcp://[::1]:%s",
                strrchr(bindEndpoint, ':') + 1);
    else
        sprintf (connectEndpoint, "tcp://127.0.0.1:%s",
                strrchr(bindEndpoint, ':') + 1);
#else
    strcpy (connectEndpoint, bindEndpoint);
#endif

    rc = zmq_connect (sc, connectEndpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, connectEndpoint);
    assert (rc == 0);
    rc = zmq_unbind (sb, bindEndpoint);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);

    /* Port wildcard, IPv4 address, IPv6 disabled */
    sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);

    rc = zmq_bind (sb, "tcp://127.0.0.1:*");
    assert (rc == 0);

    char endpoint[256];
    endpoint_len = sizeof (endpoint);
    memset(endpoint, 0, endpoint_len);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len);
    assert (rc == 0);

    rc = zmq_connect (sc, endpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, endpoint);
    assert (rc == 0);
    rc = zmq_unbind (sb, endpoint);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);

    /* Port wildcard, IPv4 address, IPv6 enabled */
    sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);

    rc = zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
    assert (rc == 0);

    rc = zmq_bind (sb, "tcp://127.0.0.1:*");
    assert (rc == 0);

    endpoint_len = sizeof (endpoint);
    memset(endpoint, 0, endpoint_len);
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len);
    assert (rc == 0);

    rc = zmq_connect (sc, endpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_disconnect (sc, endpoint);
    assert (rc == 0);
    rc = zmq_unbind (sb, endpoint);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);

    if (ipv6) {
        /* Port wildcard, IPv6 address, IPv6 enabled */
        sb = zmq_socket (ctx, ZMQ_REP);
        assert (sb);
        sc = zmq_socket (ctx, ZMQ_REQ);
        assert (sc);

        rc = zmq_setsockopt (sb, ZMQ_IPV6, &ipv6, sizeof (int));
        assert (rc == 0);
        rc = zmq_setsockopt (sc, ZMQ_IPV6, &ipv6, sizeof (int));
        assert (rc == 0);

        rc = zmq_bind (sb, "tcp://[::1]:*");
        assert (rc == 0);

        endpoint_len = sizeof (endpoint);
        memset(endpoint, 0, endpoint_len);
        rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len);
        assert (rc == 0);

        rc = zmq_connect (sc, endpoint);
        assert (rc == 0);

        bounce (sb, sc);

        rc = zmq_disconnect (sc, endpoint);
        assert (rc == 0);
        rc = zmq_unbind (sb, endpoint);
        assert (rc == 0);

        rc = zmq_close (sc);
        assert (rc == 0);
        rc = zmq_close (sb);
        assert (rc == 0);
    }

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
