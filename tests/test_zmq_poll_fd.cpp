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
#include "testutil_unity.hpp"

#include <netdb.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#endif

SETUP_TEARDOWN_TESTCONTEXT

void test_poll_fd ()
{
    int recv_socket = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    TEST_ASSERT_NOT_EQUAL (-1, recv_socket);

    int flag = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      setsockopt (recv_socket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int)));

    struct sockaddr_in saddr = bind_bsd_socket (recv_socket);

    void *sb = test_context_socket (ZMQ_REP);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "tcp://127.0.0.1:*"));

    zmq_pollitem_t pollitems[] = {
      {sb, 0, ZMQ_POLLIN, 0},
      {NULL, recv_socket, ZMQ_POLLIN, 0},
    };

    int send_socket = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    TEST_ASSERT_NOT_EQUAL (-1, send_socket);

    char buf[10];
    memset (buf, 1, 10);

    TEST_ASSERT_SUCCESS_ERRNO (sendto (
      send_socket, buf, 10, 0, (struct sockaddr *) &saddr, sizeof (saddr)));

    TEST_ASSERT_EQUAL (1, zmq_poll (pollitems, 2, 1));
    TEST_ASSERT_BITS_LOW (ZMQ_POLLIN, pollitems[0].revents);
    TEST_ASSERT_BITS_HIGH (ZMQ_POLLIN, pollitems[1].revents);

    test_context_socket_close (sb);

    close (send_socket);
    close (recv_socket);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_poll_fd);
    return UNITY_END ();
}
