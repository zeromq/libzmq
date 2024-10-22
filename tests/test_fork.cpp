/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <assert.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

SETUP_TEARDOWN_TESTCONTEXT

char connect_address[MAX_SOCKET_STRING];

#define NUM_MESSAGES 5

void test_fork ()
{
#if !defined(ZMQ_HAVE_WINDOWS)
    //  Create and bind pull socket to receive messages
    void *pull = test_context_socket (ZMQ_PULL);
    bind_loopback_ipv4 (pull, connect_address, sizeof connect_address);

    int pid = fork ();
    if (pid == 0) {
        // use regular assertions in the child process

        //  Child process
        //  Immediately close parent sockets and context
        zmq_close (pull);
        zmq_ctx_term (get_test_context ());

        //  Create new context, socket, connect and send some messages
        void *child_ctx = zmq_ctx_new ();
        assert (child_ctx);
        void *push = zmq_socket (child_ctx, ZMQ_PUSH);
        assert (push);
        int rc = zmq_connect (push, connect_address);
        assert (rc == 0);
        int count;
        for (count = 0; count < NUM_MESSAGES; count++)
            zmq_send (push, "Hello", 5, 0);

        zmq_close (push);
        zmq_ctx_destroy (child_ctx);
        exit (0);
    } else {
        //  Parent process
        int count;
        for (count = 0; count < NUM_MESSAGES; count++) {
            recv_string_expect_success (pull, "Hello", 0);
        }
        int child_status;
        while (true) {
            int rc = waitpid (pid, &child_status, 0);
            if (rc == -1 && errno == EINTR)
                continue;
            TEST_ASSERT_GREATER_THAN (0, rc);
            //  Verify the status code of the child was zero
            TEST_ASSERT_EQUAL (0, WEXITSTATUS (child_status));
            break;
        }
        test_context_socket_close (pull);
    }
#endif
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_fork);
    return UNITY_END ();
}
