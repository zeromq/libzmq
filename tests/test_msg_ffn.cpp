/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

void ffn(void *data, void *hint) {
    // Signal that ffn has been called by writing "freed" to hint
    (void) data;      //  Suppress 'unused' warnings at compile time
    memcpy(hint, (void *) "freed", 5);
}

int main (void) {
    setup_test_environment();
    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    assert (router);

    int rc = zmq_bind (router, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);

    rc = zmq_connect (dealer, "tcp://127.0.0.1:5555");
    assert (rc == 0);

    // Test that creating and closing a message triggers ffn
    zmq_msg_t msg;
    char hint[5];
    char data[255];
    memset(data, 0, 255);
    memcpy(data, (void *) "data", 4);
    memcpy(hint, (void *) "hint", 4);
    rc = zmq_msg_init_data(&msg, (void *)data, 255, ffn, (void*)hint);
    assert (rc == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    msleep (SETTLE_TIME);
    assert (memcmp(hint, "freed", 5) == 0);
    memcpy(hint, (void *) "hint", 4);

    // Making and closing a copy triggers ffn
    zmq_msg_t msg2;
    zmq_msg_init(&msg2);
    rc = zmq_msg_init_data(&msg, (void *)data, 255, ffn, (void *)hint);
    assert (rc == 0);
    rc = zmq_msg_copy(&msg2, &msg);
    assert (rc == 0);
    rc = zmq_msg_close(&msg2);
    assert (rc == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    msleep (SETTLE_TIME);
    assert (memcmp(hint, "freed", 5) == 0);
    memcpy(hint, (void *) "hint", 4);

    // Test that sending a message triggers ffn
    rc = zmq_msg_init_data(&msg, (void *)data, 255, ffn, (void *)hint);
    assert (rc == 0);

    zmq_msg_send(&msg, dealer, 0);
    char buf[255];
    rc = zmq_recv(router, buf, 255, 0);
    assert (rc > -1);
    rc = zmq_recv(router, buf, 255, 0);
    assert (rc == 255);
    assert (memcmp(data, buf, 4) == 0);

    msleep (SETTLE_TIME);
    assert (memcmp(hint, "freed", 5) == 0);
    memcpy(hint, (void *) "hint", 4);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    // Sending a copy of a message triggers ffn
    rc = zmq_msg_init(&msg2);
    assert (rc == 0);
    rc = zmq_msg_init_data(&msg, (void *)data, 255, ffn, (void *)hint);
    assert (rc == 0);
    rc = zmq_msg_copy(&msg2, &msg);
    assert (rc == 0);

    zmq_msg_send(&msg, dealer, 0);
    rc = zmq_recv(router, buf, 255, 0);
    assert (rc > -1);
    rc = zmq_recv(router, buf, 255, 0);
    assert (rc == 255);
    assert (memcmp(data, buf, 4) == 0);
    rc = zmq_msg_close(&msg2);
    assert (rc == 0);
    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    msleep (SETTLE_TIME);
    assert (memcmp(hint, "freed", 5) == 0);
    memcpy(hint, (void *) "hint", 4);

    //  Deallocate the infrastructure.
    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    return 0 ;
}

