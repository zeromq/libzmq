/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

const char *address = "tcp://127.0.0.1:6571";

#define NUM_MESSAGES 5

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
        zmq_term (ctx);

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
