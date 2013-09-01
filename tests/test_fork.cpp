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

const char* address = "tcp://127.0.0.1:6571";
void my_handler(int, siginfo_t *info, void *uap);
volatile int child_exited = 0;
volatile int child_exit_code = 0;

int main (void)
{
    int rc;
    
    setup_test_environment();
    
    printf("parent: process id = %d\n", (int)getpid());
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    void* sock = zmq_socket(ctx, ZMQ_PULL);
    assert(sock);
    
    rc = zmq_connect(sock, address);
    assert(rc == 0);
    
    // wait for io threads to be running
    usleep(100000);
    
    int pid = fork();
    if (pid == 0) {
        sleep(1);
        printf("child: process id = %d\n", (int)getpid());
        printf("child: terminating inherited context...\n");
        // close the socket, or the context gets stuck indefinitely
        zmq_close(sock);
        zmq_term(ctx);
        printf("child done\n");
        exit(0);
    } else {
        int child_status;
        while (true) {
            rc = waitpid(pid, &child_status, 0);
            if (rc == -1 && errno == EINTR) continue;
            printf("parent: child exit code = %d, rc = %d, errno = %d\n", WEXITSTATUS(child_status), rc, errno);
            assert(WEXITSTATUS(child_status) == 0);
            break;
        }
        printf("parent done.\n");
        exit(0);
    }
    return 0;
}
