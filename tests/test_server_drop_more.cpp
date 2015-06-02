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

int send_msg(zmq_msg_t* msg, void* s, int flags, int value);

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *server = zmq_socket (ctx, ZMQ_SERVER);
    void *client = zmq_socket (ctx, ZMQ_DEALER);

    int rc;

    rc = zmq_bind (server, "inproc://serverdropmore");
    assert (rc == 0);

    rc = zmq_connect (client, "inproc://serverdropmore");
    assert (rc == 0);

    zmq_msg_t msg;
    rc = zmq_msg_init (&msg);
    assert (rc == 0);

    // we will send 2 3-frames messages and then single frame message, only last one should be received
    rc = send_msg (&msg, client, ZMQ_SNDMORE, 1);
    assert(rc == 1);

    rc = send_msg (&msg, client, ZMQ_SNDMORE, 2);
    assert(rc == 1);

    rc = send_msg (&msg, client, 0, 3);
    assert(rc == 1);
    
    rc = send_msg (&msg, client, ZMQ_SNDMORE, 4);
    assert(rc == 1);

    rc = send_msg (&msg, client, ZMQ_SNDMORE, 5);
    assert(rc == 1);
    
    rc = send_msg (&msg, client, 0, 6);
    assert(rc == 1);

    rc = send_msg (&msg, client, 0, 7);
    assert(rc == 1);

    rc = zmq_msg_recv (&msg, server, 0);
    assert (rc == 1);  

    assert(zmq_msg_more(&msg) == 0);

    unsigned char* data = (unsigned char*)zmq_msg_data (&msg);      
    assert (data[0] == 7);

    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    rc = zmq_close (server);
    assert (rc == 0);

    rc = zmq_close (client);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}

int send_msg(zmq_msg_t* msg, void* s, int flags, int value)
{
    int rc = zmq_msg_close(msg);

    if (rc != 0)
        return rc;

    zmq_msg_init_size(msg, 1);

    if (rc != 0)
        return rc;

    unsigned char* data = (unsigned char*)zmq_msg_data(msg);
    data[0] = (unsigned char)value;

    return zmq_msg_send (msg, s, flags);
}
