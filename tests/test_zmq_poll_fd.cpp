/* SPDX-License-Identifier: MPL-2.0 */

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
