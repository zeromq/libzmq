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

void worker(void* s);

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server = zmq_socket (ctx, ZMQ_SERVER);
    void *server2 = zmq_socket (ctx, ZMQ_SERVER);
    void *pollfd = zmq_pollfd_new ();

    int rc;

    rc = zmq_add_pollfd (server, pollfd);
    assert (rc == 0);

    rc = zmq_add_pollfd (server2, pollfd);
    assert (rc == 0);

    zmq_pollitem_t items[] = {
        {server, 0, ZMQ_POLLIN, 0},
        {server2, 0, ZMQ_POLLIN, 0}};

    rc = zmq_bind (server, "tcp://127.0.0.1:5560");
    assert (rc == 0);
    
    rc = zmq_bind (server2, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    void* t = zmq_threadstart(worker, ctx);

    assert (rc == 0);    

    rc = zmq_pollfd_poll (pollfd, items, 2, -1);
    assert (rc == 1);

    assert (items[0].revents == ZMQ_POLLIN);
    assert (items[1].revents == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init(&msg);    
    rc = zmq_msg_recv(&msg, server, ZMQ_DONTWAIT);
    assert (rc == 1);    

    rc = zmq_pollfd_poll (pollfd, items, 2, -1);
    assert (rc == 1);

    assert (items[0].revents == 0); 
    assert (items[1].revents == ZMQ_POLLIN);

    rc = zmq_msg_recv(&msg, server2, ZMQ_DONTWAIT);
    assert (rc == 1);

    rc = zmq_pollfd_poll (pollfd, items, 2, 0);
    assert (rc == 0);

    assert (items[0].revents == 0); 
    assert (items[1].revents == 0);

    zmq_threadclose(t);

    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    rc = zmq_remove_pollfd (server, pollfd);
    assert (rc == 0);

    rc = zmq_remove_pollfd (server2, pollfd);
    assert (rc == 0);

    rc = zmq_pollfd_close (pollfd);
    assert (rc == 0);

    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (server2);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}

void worker(void* ctx)
{
    void *client = zmq_socket (ctx, ZMQ_CLIENT);

    int rc = zmq_connect (client, "tcp://127.0.0.1:5560");
    assert (rc == 0);     

    msleep(100);

    zmq_msg_t msg;
    rc = zmq_msg_init_size(&msg,1);
    assert (rc == 0);

    char * data = (char *)zmq_msg_data(&msg);
    data[0] = 1;

    rc = zmq_msg_send(&msg, client, 0);
    assert (rc == 1);

    rc = zmq_disconnect (client, "tcp://127.0.0.1:5560");
    assert (rc == 0);     

    rc = zmq_connect (client, "tcp://127.0.0.1:5561");
    assert (rc == 0);

    msleep(100);

    rc = zmq_msg_close(&msg);
    assert (rc == 0);    

    rc = zmq_msg_init_size(&msg,1);
    assert (rc == 0);

    data = (char *)zmq_msg_data(&msg);
    data[0] = 1;

    rc = zmq_msg_send(&msg, client, 0);
    assert (rc == 1);

    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);
}


