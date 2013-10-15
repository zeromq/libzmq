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

#include "testutil.hpp"

#define THREAD_COUNT 100

extern "C"
{
    static void worker (void *s)
    {
        int rc;

        rc = zmq_connect (s, "tcp://127.0.0.1:5560");
        assert (rc == 0);

        //  Start closing the socket while the connecting process is underway.
        rc = zmq_close (s);
        assert (rc == 0);
    }
}

int main (void)
{
    setup_test_environment();
    void *s1;
    void *s2;
    int i;
    int j;
    int rc;
    void* threads [THREAD_COUNT];

    for (j = 0; j != 10; j++) {

        //  Check the shutdown with many parallel I/O threads.
        void *ctx = zmq_ctx_new ();
        assert (ctx);
        zmq_ctx_set (ctx, ZMQ_IO_THREADS, 7);

        s1 = zmq_socket (ctx, ZMQ_PUB);
        assert (s1);

        rc = zmq_bind (s1, "tcp://127.0.0.1:5560");
        assert (rc == 0);

        for (i = 0; i != THREAD_COUNT; i++) {
            s2 = zmq_socket (ctx, ZMQ_SUB);
            assert (s2);
            threads [i] = zmq_threadstart(&worker, s2);
        }

        for (i = 0; i != THREAD_COUNT; i++) {
            zmq_threadclose(threads [i]);
        }

        rc = zmq_close (s1);
        assert (rc == 0);

        rc = zmq_ctx_term (ctx);
        assert (rc == 0);
    }

    return 0;
}
