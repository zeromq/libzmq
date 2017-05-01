/*:
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

//  Client threads loop on send/recv until told to exit
void client_thread (void *client)
{
    char data = 0;
    for (int count = 0; count < 15000; count++) {
        int rc = zmq_send (client, &data, 1, 0);
        assert (rc == 1);
    }
    data = 1;
    int rc = zmq_send (client, &data, 1, 0);
    assert (rc == 1);
}

int main (void)
{
    setup_test_environment ();
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server = zmq_socket (ctx, ZMQ_SERVER);
    int rc = zmq_bind (server, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (server, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    void *client = zmq_socket (ctx, ZMQ_CLIENT);
    int thread_safe;
    size_t size = sizeof (int);
    zmq_getsockopt (client, ZMQ_THREAD_SAFE, &thread_safe, &size);
    assert (thread_safe == 1);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);

    void *t1 = zmq_threadstart (client_thread, client);
    void *t2 = zmq_threadstart (client_thread, client);

    char data;
    int threads_completed = 0;
    while (threads_completed < 2) {
        zmq_recv (server, &data, 1, 0);
        if (data == 1)
            threads_completed++;            //  Thread ended
    }
    zmq_threadclose (t1);
    zmq_threadclose (t2);

    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
