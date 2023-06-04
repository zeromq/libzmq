/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

#define MSG_SIZE 20

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

void test_srcfd ()
{
    char my_endpoint[MAX_SOCKET_STRING];

    //  Create the infrastructure

    void *rep = test_context_socket (ZMQ_REP);
    void *req = test_context_socket (ZMQ_REQ);

    bind_loopback_ipv4 (rep, my_endpoint, sizeof (my_endpoint));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (req, my_endpoint));

    char tmp[MSG_SIZE];
    memset (tmp, 0, MSG_SIZE);
    zmq_send (req, tmp, MSG_SIZE, 0);

    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));

    zmq_recvmsg (rep, &msg, 0);
    TEST_ASSERT_EQUAL_UINT (MSG_SIZE, zmq_msg_size (&msg));

    // get the messages source file descriptor
    int src_fd = zmq_msg_get (&msg, ZMQ_SRCFD);
    TEST_ASSERT_GREATER_OR_EQUAL (0, src_fd);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    // get the remote endpoint
    struct sockaddr_storage ss;
#ifdef ZMQ_HAVE_HPUX
    int addrlen = sizeof ss;
#else
    socklen_t addrlen = sizeof ss;
#endif
    TEST_ASSERT_SUCCESS_RAW_ERRNO (
      getpeername (src_fd, (struct sockaddr *) &ss, &addrlen));

    char host[NI_MAXHOST];
    TEST_ASSERT_SUCCESS_RAW_ERRNO (getnameinfo ((struct sockaddr *) &ss,
                                                addrlen, host, sizeof host,
                                                NULL, 0, NI_NUMERICHOST));

    // assert it is localhost which connected
    TEST_ASSERT_EQUAL_STRING ("127.0.0.1", host);

    test_context_socket_close (rep);
    test_context_socket_close (req);

    // sleep a bit for the socket to be freed
    msleep (SETTLE_TIME);

    // getting name from closed socket will fail
#ifdef ZMQ_HAVE_WINDOWS
    const int expected_errno = WSAENOTSOCK;
#else
    const int expected_errno = EBADF;
#endif
    TEST_ASSERT_FAILURE_RAW_ERRNO (
      expected_errno, getpeername (src_fd, (struct sockaddr *) &ss, &addrlen));
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_srcfd);
    return UNITY_END ();
}
