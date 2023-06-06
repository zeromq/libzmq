/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#if defined(ZMQ_HAVE_WINDOWS)
#include <winsock2.h>
#include <stdexcept>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

SETUP_TEARDOWN_TESTCONTEXT

//  Solaris has a default of 256 max files per process
#ifdef ZMQ_HAVE_SOLARIS
#define MAX_SOCKETS 200
#else
#define MAX_SOCKETS 1000
#endif

#if defined(ZMQ_HAVE_WINDOWS)

void initialise_network (void)
{
    WSADATA info;
    if (WSAStartup (MAKEWORD (2, 0), &info) != 0)
        throw std::runtime_error ("Could not start WSA");
}

#else

void initialise_network (void)
{
}

#endif

void test_localhost ()
{
    //  Check that we have local networking via ZeroMQ
    void *dealer = test_context_socket (ZMQ_DEALER);
    if (zmq_bind (dealer, "tcp://127.0.0.1:*") == -1) {
        TEST_FAIL_MESSAGE (
          "E: Cannot find 127.0.0.1 -- your system does not have local\n"
          "E: networking. Please fix this before running libzmq checks.\n");
    }

    test_context_socket_close (dealer);
}

void test_max_sockets ()
{
    //  Check that we can create 1,000 sockets
    fd_t handle[MAX_SOCKETS];
    int count;
    for (count = 0; count < MAX_SOCKETS; count++) {
        handle[count] = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (handle[count] == retired_fd) {
            printf ("W: Only able to create %d sockets on this box\n", count);
            const char msg[] =
              "I: Tune your system to increase maximum allowed file handles\n"
#if !defined(ZMQ_HAVE_WINDOWS)
              "I: Run 'ulimit -n 1200' in bash\n"
#endif
              ;
            TEST_FAIL_MESSAGE (msg);
        }
    }
    //  Release the socket handles
    for (count = 0; count < MAX_SOCKETS; count++) {
        close (handle[count]);
    }
}

//  This test case stresses the system to shake out known configuration
//  problems. We're direct system calls when necessary. Some code may
//  need wrapping to be properly portable.

int main (void)
{
    initialise_network ();

    UNITY_BEGIN ();
    RUN_TEST (test_localhost);
    RUN_TEST (test_max_sockets);
    return UNITY_END ();
}
