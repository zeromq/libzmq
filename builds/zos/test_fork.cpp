/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include <unistd.h>           // For alarm()

const char *address = "tcp://127.0.0.1:6571";

#define NUM_MESSAGES 5
#define TIMEOUT_SECS 5        // Global timeout

int main (void)
{
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create and bind pull socket to receive messages
    void *pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    int rc = zmq_bind (pull, address);
    assert (rc == 0);

    int pid = fork ();
    if (pid == 0) {
        //  Child process
        //  Immediately close parent sockets and context
        zmq_close (pull);
        zmq_ctx_term (ctx);

        //  Create new context, socket, connect and send some messages
        void *child_ctx = zmq_ctx_new ();
        assert (child_ctx);
        void *push = zmq_socket (child_ctx, ZMQ_PUSH);
        assert (push);
        rc = zmq_connect (push, address);
        assert (rc == 0);
        int count;
        for (count = 0; count < NUM_MESSAGES; count++)
            zmq_send (push, "Hello", 5, 0);

        zmq_close (push);
        zmq_ctx_destroy (child_ctx);
        exit (0);
    }
    else {
        //  Parent process
        alarm(TIMEOUT_SECS);   // Set upper limit on runtime

        int count;
        for (count = 0; count < NUM_MESSAGES; count++) {
            char buffer [5];
            int num_bytes = zmq_recv (pull, buffer, 5, 0);
            assert (num_bytes == 5);
        }
        int child_status;
        while (true) {
            rc = waitpid (pid, &child_status, 0);
            if (rc == -1 && errno == EINTR)
                continue;
            assert (rc > 0);
            //  Verify the status code of the child was zero
            assert (WEXITSTATUS (child_status) == 0);
            break;
        }
        exit (0);
    }
    return 0;
}
