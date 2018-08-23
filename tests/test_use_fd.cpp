/*
    Copyright (c) 2016-2017 Contributors as noted in the AUTHORS file

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

#if !defined(ZMQ_HAVE_WINDOWS)
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

int setup_socket_and_set_fd (void *zmq_socket_,
                             int af_,
                             int protocol_,
                             const sockaddr *addr_,
                             size_t addr_len_)
{
    int s_pre = socket (af_, SOCK_STREAM, protocol_);
    assert (s_pre != -1);

    if (af_ == AF_INET) {
        int flag = 1;
        int rc =
          setsockopt (s_pre, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
        assert (rc == 0);
    }

    int rc = bind (s_pre, addr_, addr_len_);
    assert (rc == 0);

    rc = listen (s_pre, SOMAXCONN);
    assert (rc == 0);

    rc = zmq_setsockopt (zmq_socket_, ZMQ_USE_FD, &s_pre, sizeof (s_pre));
    assert (rc == 0);

    return s_pre;
}

typedef void (*pre_allocate_sock_fun_t) (void *, char *);

void setup_socket_pair (void *ctx_,
                        pre_allocate_sock_fun_t pre_allocate_sock_fun_,
                        int bind_socket_type_,
                        int connect_socket_type_,
                        void **out_sb_,
                        void **out_sc_)
{
    *out_sb_ = zmq_socket (ctx_, bind_socket_type_);
    assert (out_sb_);

    char my_endpoint[MAX_SOCKET_STRING];
    pre_allocate_sock_fun_ (out_sb_, my_endpoint);

    int rc = zmq_bind (out_sb_, my_endpoint);
    assert (rc == 0);

    *out_sc_ = zmq_socket (ctx_, connect_socket_type_);
    assert (out_sc_);
    rc = zmq_connect (out_sc_, my_endpoint);
    assert (rc == 0);
}

void test_socket_pair (pre_allocate_sock_fun_t pre_allocate_sock_fun_,
                       int bind_socket_type_,
                       int connect_socket_type_)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb, *sc;
    setup_socket_pair (ctx, pre_allocate_sock_fun_, bind_socket_type_,
                       connect_socket_type_, &sb, &sc);

    bounce (sb, sc);

    int rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

void test_req_rep (pre_allocate_sock_fun_t pre_allocate_sock_fun_)
{
    test_socket_pair (pre_allocate_sock_fun_, ZMQ_REP, ZMQ_REQ);
}

void test_pair (pre_allocate_sock_fun_t pre_allocate_sock_fun_)
{
    test_socket_pair (pre_allocate_sock_fun_, ZMQ_PAIR, ZMQ_PAIR);
}

void test_client_server (pre_allocate_sock_fun_t pre_allocate_sock_fun_)
{
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb, *sc;
    setup_socket_pair (ctx, pre_allocate_sock_fun_, ZMQ_SERVER, ZMQ_CLIENT, &sb,
                       &sc);

    zmq_msg_t msg;
    int rc = zmq_msg_init_size (&msg, 1);
    assert (rc == 0);

    char *data = (char *) zmq_msg_data (&msg);
    data[0] = 1;

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

    data = (char *) zmq_msg_data (&msg);
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

uint16_t pre_allocate_sock_tcp_int (void *zmq_socket_,
                                    const char *address_,
                                    const char *port_)
{
    struct addrinfo *addr, hint;
    hint.ai_flags = 0;
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_addrlen = 0;
    hint.ai_canonname = NULL;
    hint.ai_addr = NULL;
    hint.ai_next = NULL;

    int rc = getaddrinfo (address_, port_, &hint, &addr);
    assert (rc == 0);

    const int s_pre = setup_socket_and_set_fd (
      zmq_socket_, AF_INET, IPPROTO_TCP, addr->ai_addr, addr->ai_addrlen);

    struct sockaddr_in sin;
    socklen_t len = sizeof (sin);
    rc = getsockname (s_pre, (struct sockaddr *) &sin, &len);
    assert (rc != -1);

    freeaddrinfo (addr);

    return ntohs (sin.sin_port);
}

void pre_allocate_sock_tcp (void *socket_, char *my_endpoint_)
{
    const uint16_t port = pre_allocate_sock_tcp_int (socket_, "127.0.0.1", "0");
    sprintf (my_endpoint_, "tcp://127.0.0.1:%u", port);
}

void test_req_rep_tcp ()
{
    test_req_rep (pre_allocate_sock_tcp);
}

void test_pair_tcp ()
{
    test_pair (pre_allocate_sock_tcp);
}

void test_client_server_tcp ()
{
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    test_client_server (pre_allocate_sock_tcp);
#endif
}

void pre_allocate_sock_ipc_int (void *zmq_socket_, const char *path_)
{
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy (addr.sun_path, path_);

    // TODO check return value of unlink
    unlink (path_);

    setup_socket_and_set_fd (zmq_socket_, AF_UNIX, 0, (struct sockaddr *) &addr,
                             sizeof (struct sockaddr_un));
}

void pre_allocate_sock_ipc (void *sb_, char *my_endpoint_)
{
    pre_allocate_sock_ipc_int (sb_, "/tmp/test_use_fd_ipc");
    strcpy (my_endpoint_, "ipc:///tmp/test_use_fd_ipc");
}

void test_req_rep_ipc ()
{
    test_req_rep (pre_allocate_sock_ipc);

    int rc = unlink ("/tmp/test_use_fd_ipc");
    assert (rc == 0);
}

void test_pair_ipc ()
{
    test_pair (pre_allocate_sock_ipc);

    int rc = unlink ("/tmp/test_use_fd_ipc");
    assert (rc == 0);
}

void test_client_server_ipc ()
{
#if defined(ZMQ_SERVER) && defined(ZMQ_CLIENT)
    test_client_server (pre_allocate_sock_ipc);

    int rc = unlink ("/tmp/test_use_fd_ipc");
    assert (rc == 0);
#endif
}

int main ()
{
    setup_test_environment ();

    test_req_rep_tcp ();
    test_pair_tcp ();
    test_client_server_tcp ();

    test_req_rep_ipc ();
    test_pair_ipc ();
    test_client_server_ipc ();

    return 0;
}
#else
int main ()
{
    return 0;
}
#endif
