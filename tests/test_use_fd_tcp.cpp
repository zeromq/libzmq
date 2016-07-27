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

#if !defined (ZMQ_HAVE_WINDOWS)
#include <netdb.h>

void pre_allocate_sock (void *zmq_socket, const char *address,
        const char *port)
{
    struct addrinfo *addr, hint;
    hint.ai_flags=0;
    hint.ai_family=AF_INET;
    hint.ai_socktype=SOCK_STREAM;
    hint.ai_protocol=IPPROTO_TCP;
    hint.ai_addrlen=0;
    hint.ai_canonname=NULL;
    hint.ai_addr=NULL;
    hint.ai_next=NULL;

    int rc = getaddrinfo (address, port, &hint, &addr);
    assert (rc == 0);

    int s_pre = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert (s_pre != -1);

    int flag = 1;
    rc = setsockopt (s_pre, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
    assert (rc == 0);

    rc = bind (s_pre, addr->ai_addr, addr->ai_addrlen);
    assert (rc == 0);

    rc = listen (s_pre, SOMAXCONN);
    assert (rc == 0);

    rc = zmq_setsockopt (zmq_socket, ZMQ_USE_FD, &s_pre,
            sizeof (s_pre));
    assert(rc == 0);

    freeaddrinfo(addr);
}

void test_req_rep ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);

    pre_allocate_sock(sb, "127.0.0.1", "5560");

    int rc = zmq_bind (sb, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_pair ()
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_PAIR);
    assert (sb);

    pre_allocate_sock(sb, "127.0.0.1", "5560");

    int rc = zmq_bind (sb, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_PAIR);
    assert (sc);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_client_server ()
{
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_SERVER);
    assert (sb);

    pre_allocate_sock(sb, "127.0.0.1", "5560");

    int rc = zmq_bind (sb, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_CLIENT);
    assert (sc);
    rc = zmq_connect (sc, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init_size (&msg, 1);
    assert (rc == 0);

    char *data = (char *) zmq_msg_data (&msg);
    data [0] = 1;

    rc = zmq_msg_send (&msg, sc, ZMQ_SNDMORE);
    assert (rc == -1);

    rc = zmq_msg_send (&msg, sc, 0);
    assert (rc == 1);

    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    rc = zmq_msg_recv (&msg, sb, 0);
    assert (rc == 1);

    uint32_t routing_id = zmq_msg_routing_id (&msg);
    assert (routing_id != 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_msg_init_size (&msg, 1);
    assert (rc == 0);

    data = (char *)zmq_msg_data (&msg);
    data[0] = 2;

    rc = zmq_msg_set_routing_id (&msg, routing_id);
    assert (rc == 0);

    rc = zmq_msg_send (&msg, sb, ZMQ_SNDMORE);
    assert (rc == -1);

    rc = zmq_msg_send (&msg, sb, 0);
    assert (rc == 1);

    rc = zmq_msg_recv (&msg, sc, 0);
    assert (rc == 1);

    routing_id = zmq_msg_routing_id (&msg);
    assert (routing_id == 0);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
#endif
}

int main (void)
{
    setup_test_environment();

    test_req_rep();
    test_pair();
    test_client_server();

    return 0 ;
}
#else
int main (void)
{
    return 0 ;
}
#endif
