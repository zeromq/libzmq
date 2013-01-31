/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <zmq.h>
#include <unistd.h>
#include <poll.h>

//ToDo: Windows?
const char *test_str = "TEST-STRING";

int tcp_client (void)
{
    struct sockaddr_in serv_addr;
    struct hostent *server;

    const int portno = 5555;

    int sockfd = socket (AF_INET, SOCK_STREAM, 0);
    assert (sockfd >= 0);
    server = gethostbyname ("localhost");
    assert (server);

    memset (&serv_addr, 0, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;
    memmove (&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons (portno);

    int rc = connect (sockfd, (struct sockaddr *) &serv_addr, sizeof serv_addr);
    assert (rc == 0);
    int nodelay = 1;
    rc = setsockopt (sockfd, IPPROTO_TCP, TCP_NODELAY, (char*) &nodelay,
        sizeof nodelay);
    assert (rc == 0);

    return sockfd;
}

int tcp_server (void)
{
    int listenfd = socket (AF_INET, SOCK_STREAM, 0);
    assert (listenfd != -1);

    int flag = 1;
    int rc = setsockopt (listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof flag);
    assert (rc == 0);

    struct sockaddr_in serv_addr;
    memset (&serv_addr, 0, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
    serv_addr.sin_port = htons (5555);

    rc = bind (listenfd, (struct sockaddr *) &serv_addr, sizeof serv_addr);
    assert (rc == 0);

    rc = listen (listenfd, 8);
    assert (rc == 0);

    int sockfd = accept (listenfd, NULL, NULL);
    assert (sockfd != -1);

    rc = close (listenfd);
    assert (rc == 0);

    int flags = fcntl (sockfd, F_GETFL, 0);
    if (flags == -1)
        flags = 0;
    rc = fcntl (sockfd, F_SETFL, flags | O_NONBLOCK);
    assert (rc != -1);

    return sockfd;
}

void tcp_client_write (int sockfd, const void *buf, int buf_len)
{
    assert (buf);
    int n = write (sockfd, buf, buf_len);
    assert (n >= 0);
}

void tcp_client_read (int sockfd)
{
    struct timeval tm;
    tm.tv_sec = 1;
    tm.tv_usec = 0;
    fd_set r;

    char buffer [16];

    FD_ZERO (&r);
    FD_SET (sockfd, &r);

    int sr = select (sockfd + 1, &r, NULL, NULL, &tm);
    assert (sr > 0);

    int n = read (sockfd, buffer, 16);
    assert (n > 0);
    assert (memcmp (buffer, test_str, strlen (test_str)) == 0);
}

size_t tcp_read (int s, char *buf, size_t bufsize)
{
    size_t total_size = 0;
    struct pollfd pfd = { s, POLLIN };
    int rc = poll (&pfd, 1, 1000);
    assert (rc > 0);

    while (rc > 0 && total_size < bufsize) {
        int chunk_size = read (s, buf + total_size, bufsize - total_size);
        assert (chunk_size >= 0);
        total_size += chunk_size;
        rc = poll (&pfd, 1, 1000);
    }
    return total_size;
}

void tcp_client_close (int sockfd)
{
    close (sockfd);
}

void test_zmq_connect (void)
{
    void *ctx = zmq_init (1);
    assert (ctx);

    void *zs = zmq_socket (ctx, ZMQ_ROUTER);
    assert (zs);

    int rc = zmq_setsockopt (zs, ZMQ_IDENTITY, "X", 1);
    assert (rc == 0);

    int raw_sock = 1;
    rc = zmq_setsockopt (zs, ZMQ_ROUTER_RAW, &raw_sock, sizeof raw_sock);
    assert (rc == 0);

    rc = zmq_connect (zs, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    int i;
    for (i = 0; i < 8; i++) {
        int server_fd = tcp_server ();
        assert (server_fd != -1);

        zmq_msg_t msg;
        rc = zmq_msg_init_size (&msg, strlen (test_str));
        assert (rc == 0);
        memcpy (zmq_msg_data (&msg), test_str, strlen (test_str));
        rc = zmq_msg_send (&msg, zs, 0);

        char buffer [128];
        size_t bytes_read = tcp_read (server_fd, buffer, sizeof buffer);

        assert (bytes_read == strlen (test_str));
        assert (memcmp (buffer, test_str, bytes_read) == 0);

        rc = close (server_fd);
        assert (rc == 0);
    }

    rc = zmq_close (zs);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    fprintf (stderr, "test_raw_sock running...\n");

    zmq_msg_t message;
    zmq_msg_t id;

    //===================
    void *ctx = zmq_init (1);
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_ROUTER);
    assert (sb);

    int raw_sock = 1;
    int rc = zmq_setsockopt (sb, ZMQ_ROUTER_RAW, &raw_sock, sizeof raw_sock);
    assert (rc == 0);
    rc = zmq_bind (sb, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    int sock_fd = tcp_client ();
    assert (sock_fd >= 0);
    // ===================

    zmq_msg_init (&message);
    zmq_msg_init (&id);
    assert (rc == 0);

    zmq_pollitem_t items [] = {
        { sb, 0, ZMQ_POLLIN, 0 },
    };

    tcp_client_write (sock_fd, test_str, strlen (test_str));
    zmq_poll (items, 1, 500);
    assert (items [0].revents & ZMQ_POLLIN);
    int n = zmq_msg_recv (&id, sb, 0);
    assert (n > 0);
    n = zmq_msg_recv (&message, sb, 0);
    assert (n > 0);
    assert (memcmp (zmq_msg_data (&message), test_str, strlen (test_str)) == 0);

    zmq_msg_send (&id, sb, ZMQ_SNDMORE);
    zmq_msg_send (&message, sb, ZMQ_SNDMORE); // SNDMORE option is ignored

    tcp_client_read (sock_fd);
    tcp_client_close (sock_fd);

    zmq_msg_close (&id);
    zmq_msg_close (&message);

    zmq_close (sb);
    zmq_term (ctx);

    test_zmq_connect ();

    fprintf (stderr, "test_raw_sock PASSED.\n");

    return 0;
}
