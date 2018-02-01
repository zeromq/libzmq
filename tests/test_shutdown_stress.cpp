/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#define THREAD_COUNT 100

struct thread_data
{
    void *ctx;
    char endpoint[MAX_SOCKET_STRING];
};

extern "C" {
static void worker (void *data)
{
    int rc;
    void *socket;
    struct thread_data *tdata = (struct thread_data *) data;

    socket = zmq_socket (tdata->ctx, ZMQ_SUB);
    assert (socket);

    rc = zmq_connect (socket, tdata->endpoint);
    assert (rc == 0);

    //  Start closing the socket while the connecting process is underway.
    rc = zmq_close (socket);
    assert (rc == 0);
}
}

int main (void)
{
    setup_test_environment ();
    void *socket;
    int i;
    int j;
    int rc;
    void *threads[THREAD_COUNT];

    for (j = 0; j != 10; j++) {
        //  Check the shutdown with many parallel I/O threads.
        struct thread_data tdata;
        tdata.ctx = zmq_ctx_new ();
        assert (tdata.ctx);
        zmq_ctx_set (tdata.ctx, ZMQ_IO_THREADS, 7);

        socket = zmq_socket (tdata.ctx, ZMQ_PUB);
        assert (socket);

        rc = zmq_bind (socket, "tcp://127.0.0.1:*");
        assert (rc == 0);
        size_t len = MAX_SOCKET_STRING;
        rc = zmq_getsockopt (socket, ZMQ_LAST_ENDPOINT, tdata.endpoint, &len);
        assert (rc == 0);

        for (i = 0; i != THREAD_COUNT; i++) {
            threads[i] = zmq_threadstart (&worker, &tdata);
        }

        for (i = 0; i != THREAD_COUNT; i++) {
            zmq_threadclose (threads[i]);
        }

        rc = zmq_close (socket);
        assert (rc == 0);

        rc = zmq_ctx_term (tdata.ctx);
        assert (rc == 0);
    }

    return 0;
}
