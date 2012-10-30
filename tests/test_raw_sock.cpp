/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2011 250bpm s.r.o.
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

//ToDo: Windows?
const char *test_str = "TEST-STRING";

int tcp_client ()
{
    struct sockaddr_in serv_addr;
    struct hostent *server;

    const int portno = 5555;

    int sockfd = socket (AF_INET, SOCK_STREAM, 0);
    assert (sockfd >= 0);
    server = gethostbyname ("localhost");
    assert (server);

    bzero (&serv_addr, sizeof serv_addr);
    serv_addr.sin_family = AF_INET;
    bcopy (server->h_addr, &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons (portno);

    int rc = connect (sockfd, (struct sockaddr *) &serv_addr, sizeof serv_addr);
    assert (rc == 0);
    int nodelay = 1;
    rc = setsockopt (sockfd, IPPROTO_TCP, TCP_NODELAY, (char*) &nodelay,
        sizeof nodelay);
    assert (rc == 0);

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

void tcp_client_close (int sockfd)
{
    close (sockfd);
}

int main ()
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
    int rc = zmq_setsockopt (sb, ZMQ_ROUTER_RAW_SOCK, &raw_sock, sizeof raw_sock);
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

    fprintf (stderr, "test_raw_sock PASSED.\n");

    return 0;
}
