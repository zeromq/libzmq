/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include "../include/zmq.h"
#include "../include/zmq_utils.h"
#include <stdio.h>
#include <string.h>
#include "testutil.hpp"
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>

const char* address = "tcp://127.0.0.1:6571";

#define NUM_MESSAGES 5

int main (void)
{
    int rc;

    setup_test_environment();

    printf("parent: process id = %d\n", (int)getpid());
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void* sock = zmq_socket(ctx, ZMQ_PULL);
    assert(sock);

    rc = zmq_bind(sock, address);
    assert(rc == 0);

    // wait for io threads to be running
    usleep(100000);

    printf("about to fork()\n");
    int pid = fork();
    if (pid == 0) {
        // this is the child process

        usleep(100000);
        printf("child: process id = %d\n", (int)getpid());
        printf("child: terminating inherited context...\n");
        // close the socket, or the context gets stuck indefinitely
        // zmq_close(sock);
        zmq_term(ctx);

        // create new context, socket, connect and send some messages
        void *ctx2 = zmq_ctx_new ();
        assert (ctx2);

        void* push = zmq_socket(ctx2, ZMQ_PUSH);
        assert(push);

        rc = zmq_connect(push, address);
        assert(rc == 0);

        const char* message = "hello";

        int i;
        for (i = 0; i < NUM_MESSAGES; i += 1) {
            printf("child: send message #%d\n", i);
            zmq_send(push, message, strlen(message), 0);
            usleep(100000);
        }

        printf("child: closing push socket\n");
        zmq_close(push);
        printf("child: destroying child context\n");
        zmq_ctx_destroy(ctx2);
        printf("child: done\n");
        exit(0);
    } else {
        // this is the parent process
        printf("parent: waiting for %d messages\n", NUM_MESSAGES);

        char buffer[1024];

        int i;
        for (i = 0; i < NUM_MESSAGES; i += 1) {
            int num_bytes = zmq_recv(sock, buffer, 1024, 0);
            assert(num_bytes > 0);
            buffer[num_bytes] = 0;
            printf("parent: received #%d: %s\n", i, buffer);
        }

        int child_status;
        while (true) {
            rc = waitpid(pid, &child_status, 0);
            if (rc == -1 && errno == EINTR) continue;
            printf("parent: child exit code = %d, rc = %d, errno = %d\n", WEXITSTATUS(child_status), rc, errno);
            assert(rc > 0);
            // verify the status code of the child was zero.
            assert(WEXITSTATUS(child_status) == 0);
            break;
        }
        printf("parent: done.\n");
        exit(0);
    }
    return 0;
}
