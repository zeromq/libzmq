/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include <assert.h>
#include <string.h>

#include "../include/zmq.h"
#include "../include/zmq_utils.h"

void listening_sock_monitor (void *s, int event_, zmq_event_data_t *data_)
{
    const char *addr = "tcp://127.0.0.1:5560";
    // Only some of the exceptional events could fire
    switch (event_) {
    case ZMQ_EVENT_LISTENING:
        assert (data_->listening.fd > 0);
        assert (memcmp (data_->listening.addr, addr, 22));
        break;
    case ZMQ_EVENT_ACCEPTED:
        assert (data_->accepted.fd > 0);
        assert (memcmp (data_->accepted.addr, addr, 22));
        break;
    case ZMQ_EVENT_CLOSE_FAILED:
        assert (data_->close_failed.err != 0);
        assert (memcmp (data_->close_failed.addr, addr, 22));
        break;
    case ZMQ_EVENT_CLOSED:
        assert (data_->closed.fd != 0);
        assert (memcmp (data_->closed.addr, addr, 22));
        break;
    case ZMQ_EVENT_DISCONNECTED:
        assert (data_->disconnected.fd != 0);
        assert (memcmp (data_->disconnected.addr, addr, 22));
        break;
    default:
        // out of band / unexpected event
        assert (0);
    }
}

void connecting_sock_monitor (void *s, int event_, zmq_event_data_t *data_)
{
    const char *addr = "tcp://127.0.0.1:5560";
    // Only some of the exceptional events could fire
    switch (event_) {
    case ZMQ_EVENT_CONNECTED:
        assert (data_->connected.fd > 0);
        assert (memcmp (data_->connected.addr, addr, 22));
        break;
    case ZMQ_EVENT_CONNECT_DELAYED:
        assert (data_->connect_delayed.err != 0);
        assert (memcmp (data_->connect_delayed.addr, addr, 22));
        break;
    case ZMQ_EVENT_CLOSE_FAILED:
        assert (data_->close_failed.err != 0);
        assert (memcmp (data_->close_failed.addr, addr, 22));
        break;
    case ZMQ_EVENT_CLOSED:
        assert (data_->closed.fd != 0);
        assert (memcmp (data_->closed.addr, addr, 22));
        break;
    case ZMQ_EVENT_DISCONNECTED:
        assert (data_->disconnected.fd != 0);
        assert (memcmp (data_->disconnected.addr, addr, 22));
        break;
    default:
        // out of band / unexpected event
        assert (0);
    }
}

int main (int argc, char *argv [])
{
    int rc;

    //  Create the infrastructure
    void *ctx = zmq_init (1);
    assert (ctx);

    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    // Expects failure - invalid size
    zmq_monitor_fn monitor;
    monitor.function = listening_sock_monitor;

    rc = zmq_setsockopt (rep, ZMQ_MONITOR, &monitor, 20);
    assert (rc == -1);
    assert (errno == EINVAL);

    rc = zmq_setsockopt (rep, ZMQ_MONITOR, &monitor, sizeof (void *));
    assert (rc == 0);

    size_t sz = sizeof (void *);
    rc = zmq_getsockopt (rep, ZMQ_MONITOR, &monitor, &sz);
    assert (rc == 0);
    assert (monitor.function == listening_sock_monitor);

    // Remove socket monitor callback
    rc = zmq_setsockopt (rep, ZMQ_MONITOR, NULL, 0);
    assert (rc == 0);

    rc = zmq_getsockopt (rep, ZMQ_MONITOR, &monitor, &sz);
    assert (rc == 0);
    assert (monitor.function == listening_sock_monitor);

    rc = zmq_bind (rep, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    monitor.function = connecting_sock_monitor;
    rc = zmq_setsockopt (req, ZMQ_MONITOR, &monitor, sizeof (void *));
    assert (rc == 0);

    rc = zmq_connect (req, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    // Allow a window for socket events as connect can be async
    zmq_sleep (1);

    //  Deallocate the infrastructure.
    rc = zmq_close (req);
    assert (rc == 0);

    // Allow for closed or disconnected events to bubble up
    zmq_sleep (1);

    rc = zmq_close (rep);
    assert (rc == 0);

    zmq_sleep (1);

    zmq_term (ctx);
    return 0 ;
}