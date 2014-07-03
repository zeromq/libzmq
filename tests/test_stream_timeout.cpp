/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.

static int
get_monitor_event (void *monitor, int *value, char **address)
{
    //  First frame in message contains event number and value
    zmq_msg_t msg; 
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (zmq_msg_more (&msg));
    
    uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
    uint16_t event = *(uint16_t *) (data);
    if (value)
        *value = *(uint32_t *) (data + 2);

    //  Second frame in message contains event address
    zmq_msg_init (&msg);
    if (zmq_msg_recv (&msg, monitor, 0) == -1)
        return -1;              //  Interruped, presumably
    assert (!zmq_msg_more (&msg));
    
    if (address) {
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        size_t size = zmq_msg_size (&msg);
        *address = (char *) malloc (size + 1);
        memcpy (*address, data, size);
        *address [size] = 0;
    }
    return event;
}

static void
test_stream_handshake_timeout_accept (void)
{
    int rc;

    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We use this socket in raw mode, to make a connection and send nothing
    void *stream = zmq_socket (ctx, ZMQ_STREAM);
    assert (stream);

    int zero = 0;
    rc = zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_connect (stream, "tcp://localhost:5557");
    assert (rc == 0);

    //  We'll be using this socket to test TCP stream handshake timeout
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    int val, tenth = 100;
    size_t vsize = sizeof(val);

    // check for the expected default handshake timeout value - 30 sec
    rc = zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize);
    assert (rc == 0);
    assert (vsize == sizeof(val));
    assert (val == 30000);
    // make handshake timeout faster - 1/10 sec
    rc = zmq_setsockopt (dealer, ZMQ_HANDSHAKE_IVL, &tenth, sizeof (tenth));
    assert (rc == 0);
    vsize = sizeof(val);
    // make sure zmq_setsockopt changed the value
    rc = zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize);
    assert (rc == 0);
    assert (vsize == sizeof(val));
    assert (val == tenth);

    //  Create and connect a socket for collecting monitor events on dealer
    void *dealer_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (dealer_mon);

    rc = zmq_socket_monitor (dealer, "inproc://monitor-dealer",
          ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_ACCEPTED);
    assert (rc == 0);

    //  Connect to the inproc endpoint so we'll get events
    rc = zmq_connect (dealer_mon, "inproc://monitor-dealer");
    assert (rc == 0);

    // bind dealer socket to accept connection from non-sending stream socket
    rc = zmq_bind (dealer, "tcp://127.0.0.1:5557");
    assert (rc == 0);

    // we should get ZMQ_EVENT_ACCEPTED and then ZMQ_EVENT_DISCONNECTED
    int event = get_monitor_event (dealer_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_ACCEPTED);
    event = get_monitor_event (dealer_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_DISCONNECTED);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_close (dealer_mon);
    assert (rc == 0);

    rc = zmq_close (stream);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

static void
test_stream_handshake_timeout_connect (void)
{
    int rc;

    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  We use this socket in raw mode, to accept a connection and send nothing
    void *stream = zmq_socket (ctx, ZMQ_STREAM);
    assert (stream);

    int zero = 0;
    rc = zmq_setsockopt (stream, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    rc = zmq_bind (stream, "tcp://127.0.0.1:5556");
    assert (rc == 0);

    //  We'll be using this socket to test TCP stream handshake timeout
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    rc = zmq_setsockopt (dealer, ZMQ_LINGER, &zero, sizeof (zero));
    assert (rc == 0);
    int val, tenth = 100;
    size_t vsize = sizeof(val);

    // check for the expected default handshake timeout value - 30 sec
    rc = zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize);
    assert (rc == 0);
    assert (vsize == sizeof(val));
    assert (val == 30000);
    // make handshake timeout faster - 1/10 sec
    rc = zmq_setsockopt (dealer, ZMQ_HANDSHAKE_IVL, &tenth, sizeof (tenth));
    assert (rc == 0);
    vsize = sizeof(val);
    // make sure zmq_setsockopt changed the value
    rc = zmq_getsockopt (dealer, ZMQ_HANDSHAKE_IVL, &val, &vsize);
    assert (rc == 0);
    assert (vsize == sizeof(val));
    assert (val == tenth);

    //  Create and connect a socket for collecting monitor events on dealer
    void *dealer_mon = zmq_socket (ctx, ZMQ_PAIR);
    assert (dealer_mon);

    rc = zmq_socket_monitor (dealer, "inproc://monitor-dealer",
          ZMQ_EVENT_CONNECTED | ZMQ_EVENT_DISCONNECTED | ZMQ_EVENT_ACCEPTED);
    assert (rc == 0);

    //  Connect to the inproc endpoint so we'll get events
    rc = zmq_connect (dealer_mon, "inproc://monitor-dealer");
    assert (rc == 0);

    // connect dealer socket to non-sending stream socket
    rc = zmq_connect (dealer, "tcp://localhost:5556");
    assert (rc == 0);

    // we should get ZMQ_EVENT_CONNECTED and then ZMQ_EVENT_DISCONNECTED
    int event = get_monitor_event (dealer_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_CONNECTED);
    event = get_monitor_event (dealer_mon, NULL, NULL);
    assert (event == ZMQ_EVENT_DISCONNECTED);

    rc = zmq_close (dealer);
    assert (rc == 0);

    rc = zmq_close (dealer_mon);
    assert (rc == 0);

    rc = zmq_close (stream);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();
    test_stream_handshake_timeout_accept ();
    test_stream_handshake_timeout_connect ();
}
