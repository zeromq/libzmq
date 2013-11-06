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

// REQ socket events handled
static int req_socket_events;
// 2nd REQ socket events handled
static int req2_socket_events;
// REP socket events handled
static int rep_socket_events;

std::string addr ;

static bool read_msg(void* s, zmq_event_t& event, std::string& ep)
{
    int rc ;
    zmq_msg_t msg1;  // binary part
    zmq_msg_init (&msg1);
    zmq_msg_t msg2;  //  address part
    zmq_msg_init (&msg2);
    rc = zmq_msg_recv (&msg1, s, 0);
    if (rc == -1 && zmq_errno() == ETERM)
        return true ;

    assert (rc != -1);
    assert (zmq_msg_more(&msg1) != 0);
    rc = zmq_msg_recv (&msg2, s, 0);
    if (rc == -1 && zmq_errno() == ETERM)
        return true;

    assert (rc != -1);
    assert (zmq_msg_more(&msg2) == 0);
    // copy binary data to event struct
    const char* data = (char*)zmq_msg_data(&msg1);
    memcpy(&event.event, data, sizeof(event.event));
    memcpy(&event.value, data+sizeof(event.event), sizeof(event.value));
    // copy address part
    ep = std::string((char*)zmq_msg_data(&msg2), zmq_msg_size(&msg2));

    if (event.event == ZMQ_EVENT_MONITOR_STOPPED)
        return true;

    return false;
}


// REQ socket monitor thread
static void req_socket_monitor (void *ctx)
{
    zmq_event_t event;
    std::string ep ;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.req");
    assert (rc == 0);
    while (!read_msg(s, event, ep)) {
        assert (ep == addr);
        switch (event.event) {
            case ZMQ_EVENT_CONNECTED:
                assert (event.value > 0);
                req_socket_events |= ZMQ_EVENT_CONNECTED;
                req2_socket_events |= ZMQ_EVENT_CONNECTED;
                break;
            case ZMQ_EVENT_CONNECT_DELAYED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CONNECT_DELAYED;
                break;
            case ZMQ_EVENT_CLOSE_FAILED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CLOSE_FAILED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CLOSED;
                break;
            case ZMQ_EVENT_DISCONNECTED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_DISCONNECTED;
                break;
        }
    }
    zmq_close (s);
}

// 2nd REQ socket monitor thread
static void req2_socket_monitor (void *ctx)
{
    zmq_event_t event;
    std::string ep ;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.req2");
    assert (rc == 0);
    while (!read_msg(s, event, ep)) {
        assert (ep == addr);
        switch (event.event) {
            case ZMQ_EVENT_CONNECTED:
                assert (event.value > 0);
                req2_socket_events |= ZMQ_EVENT_CONNECTED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                req2_socket_events |= ZMQ_EVENT_CLOSED;
                break;
        }
    }
    zmq_close (s);
}

// REP socket monitor thread
static void rep_socket_monitor (void *ctx)
{
    zmq_event_t event;
    std::string ep ;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.rep");
    assert (rc == 0);
    while (!read_msg(s, event, ep)) {
        assert (ep == addr);
        switch (event.event) {
            case ZMQ_EVENT_LISTENING:
                assert (event.value > 0);
                rep_socket_events |= ZMQ_EVENT_LISTENING;
                break;
            case ZMQ_EVENT_ACCEPTED:
                assert (event.value > 0);
                rep_socket_events |= ZMQ_EVENT_ACCEPTED;
                break;
            case ZMQ_EVENT_CLOSE_FAILED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_CLOSE_FAILED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_CLOSED;
                break;
            case ZMQ_EVENT_DISCONNECTED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_DISCONNECTED;
                break;
        }
    }
    zmq_close (s);
}

int main (void)
{
    setup_test_environment();
    int rc;
    void *req;
    void *req2;
    void *rep;
    void* threads [3];

    addr = "tcp://127.0.0.1:5560";

    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // REP socket
    rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    // Assert supported protocols
    rc =  zmq_socket_monitor (rep, addr.c_str(), 0);
    assert (rc == -1);
    assert (zmq_errno() == EPROTONOSUPPORT);

    // Deregister monitor
    rc =  zmq_socket_monitor (rep, NULL, 0);
    assert (rc == 0);

    // REP socket monitor, all events
    rc = zmq_socket_monitor (rep, "inproc://monitor.rep", ZMQ_EVENT_ALL);
    assert (rc == 0);
    threads [0] = zmq_threadstart(&rep_socket_monitor, ctx);
    
    // REQ socket
    req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    // REQ socket monitor, all events
    rc = zmq_socket_monitor (req, "inproc://monitor.req", ZMQ_EVENT_ALL);
    assert (rc == 0);
    threads [1] = zmq_threadstart(&req_socket_monitor, ctx);
    msleep (SETTLE_TIME);

    // Bind REQ and REP
    rc = zmq_bind (rep, addr.c_str());
    assert (rc == 0);

    rc = zmq_connect (req, addr.c_str());
    assert (rc == 0);

    bounce (rep, req);
    
    // 2nd REQ socket
    req2 = zmq_socket (ctx, ZMQ_REQ);
    assert (req2);

    // 2nd REQ socket monitor, connected event only
    rc = zmq_socket_monitor (req2, "inproc://monitor.req2", ZMQ_EVENT_CONNECTED);
    assert (rc == 0);
    threads [2] = zmq_threadstart(&req2_socket_monitor, ctx);

    rc = zmq_connect (req2, addr.c_str());
    assert (rc == 0);

    // Close the REP socket
    rc = zmq_close (rep);
    assert (rc == 0);

    // Allow enough time for detecting error states
    msleep (250);

    //  Close the REQ socket
    rc = zmq_close (req);
    assert (rc == 0);

    //  Close the 2nd REQ socket
    rc = zmq_close (req2);
    assert (rc == 0);

    zmq_ctx_term (ctx);

    // Expected REP socket events
    assert (rep_socket_events & ZMQ_EVENT_LISTENING);
    assert (rep_socket_events & ZMQ_EVENT_ACCEPTED);
    assert (rep_socket_events & ZMQ_EVENT_CLOSED);

    // Expected REQ socket events
    assert (req_socket_events & ZMQ_EVENT_CONNECTED);
    assert (req_socket_events & ZMQ_EVENT_DISCONNECTED);
    assert (req_socket_events & ZMQ_EVENT_CLOSED);

    // Expected 2nd REQ socket events
    assert (req2_socket_events & ZMQ_EVENT_CONNECTED);
    assert (!(req2_socket_events & ZMQ_EVENT_CLOSED));

    for (unsigned int i = 0; i < 3; ++i)
        zmq_threadclose(threads [i]);

    return 0 ;
}
