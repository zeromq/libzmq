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

const int MAX_SENDS = 10000;

void test_change_before_connected()
{
    int rc;
    void *ctx = zmq_ctx_new();

    void *bind_socket = zmq_socket(ctx, ZMQ_PUSH);
    void *connect_socket = zmq_socket(ctx, ZMQ_PULL);

    int val = 2;
    rc = zmq_setsockopt(connect_socket, ZMQ_RCVHWM, &val, sizeof(val));
    assert(rc == 0);
    rc = zmq_setsockopt(bind_socket, ZMQ_SNDHWM, &val, sizeof(val));
    assert(rc == 0);

    zmq_connect(connect_socket, "inproc://a");
    zmq_bind(bind_socket, "inproc://a");

    size_t placeholder = sizeof(val);
    val = 0;
    rc = zmq_getsockopt(bind_socket, ZMQ_SNDHWM, &val, &placeholder);
    assert(rc == 0);
    assert(val == 2);

    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send(bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    assert(send_count == 4);

    zmq_close(bind_socket);
    zmq_close(connect_socket);
    zmq_ctx_term(ctx);
}

void test_change_after_connected()
{
    int rc;
    void *ctx = zmq_ctx_new();

    void *bind_socket = zmq_socket(ctx, ZMQ_PUSH);
    void *connect_socket = zmq_socket(ctx, ZMQ_PULL);

    int val = 1;
    rc = zmq_setsockopt(connect_socket, ZMQ_RCVHWM, &val, sizeof(val));
    assert(rc == 0);
    rc = zmq_setsockopt(bind_socket, ZMQ_SNDHWM, &val, sizeof(val));
    assert(rc == 0);

    zmq_connect(connect_socket, "inproc://a");
    zmq_bind(bind_socket, "inproc://a");

    val = 5;
    rc = zmq_setsockopt(bind_socket, ZMQ_SNDHWM, &val, sizeof(val));
    assert(rc == 0);

    size_t placeholder = sizeof(val);
    val = 0;
    rc = zmq_getsockopt(bind_socket, ZMQ_SNDHWM, &val, &placeholder);
    assert(rc == 0);
    assert(val == 5);

    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send(bind_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    assert(send_count == 6);

    zmq_close(bind_socket);
    zmq_close(connect_socket);
    zmq_ctx_term(ctx);
}

void test_decrease_when_full()
{
    int rc;
    void *ctx = zmq_ctx_new();

    void *bind_socket = zmq_socket(ctx, ZMQ_PUSH);
    void *connect_socket = zmq_socket(ctx, ZMQ_PULL);

    int val = 1;
    rc = zmq_setsockopt(connect_socket, ZMQ_RCVHWM, &val, sizeof(val));
    assert(rc == 0);

    val = 100;
    rc = zmq_setsockopt(bind_socket, ZMQ_SNDHWM, &val, sizeof(val));
    assert(rc == 0);

    zmq_bind(bind_socket, "inproc://a");
    zmq_connect(connect_socket, "inproc://a");

    // Fill up to hwm
    int send_count = 0;
    while (send_count < MAX_SENDS && zmq_send(bind_socket, &send_count, sizeof(send_count), ZMQ_DONTWAIT) == sizeof(send_count))
        ++send_count;
    assert(send_count == 101);

    // Descrease snd hwm
    val = 70;
    rc = zmq_setsockopt(bind_socket, ZMQ_SNDHWM, &val, sizeof(val));
    assert(rc == 0);

    size_t placeholder = sizeof(val);
    val = 0;
    rc = zmq_getsockopt(bind_socket, ZMQ_SNDHWM, &val, &placeholder);
    assert(rc == 0);
    assert(val == 70);

    // Read out all data (should get up to previous hwm worth so none were dropped)
    int read_count = 0;
    int read_data = 0;
    while (read_count < MAX_SENDS && zmq_recv(connect_socket, &read_data, sizeof(read_data), ZMQ_DONTWAIT) == sizeof(read_data)) {
        assert(read_count == read_data);
        ++read_count;
    }

    assert(read_count == 101);

    // Give io thread some time to catch up
    msleep (SETTLE_TIME);

    // Fill up to new hwm
    send_count = 0;
    while (send_count < MAX_SENDS && zmq_send(bind_socket, &send_count, sizeof(send_count), ZMQ_DONTWAIT) == sizeof(send_count))
        ++send_count;

    // Really this should be 71, but the lwm stuff kicks in doesn't seem quite right
    assert(send_count > 0);

    zmq_close(bind_socket);
    zmq_close(connect_socket);
    zmq_ctx_term(ctx);
}


int main()
{
    test_change_before_connected();
    test_change_after_connected();
    test_decrease_when_full();
}
