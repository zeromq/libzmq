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

int main (void) {
    setup_test_environment();
    void *ctx = zmq_ctx_new();
    assert(ctx);
    
    void *router = zmq_socket(ctx, ZMQ_ROUTER);
    assert(router);
    void *dealer = zmq_socket(ctx, ZMQ_DEALER);
    assert(dealer);
    
    int one=1;
    int rc = zmq_setsockopt(router, ZMQ_ROUTER_RAW, &one, sizeof(int));
    assert(rc >= 0);
    rc = zmq_setsockopt(router, ZMQ_ROUTER_MANDATORY, &one, sizeof(int));
    assert(rc >= 0);
    
    rc = zmq_bind(router, "tcp://127.0.0.1:5555");
    rc = zmq_connect(dealer, "tcp://127.0.0.1:5555");
    zmq_send(dealer, "", 0, 0);
    
    
    zmq_msg_t ident, empty;
    zmq_msg_init(&ident);
    rc = zmq_msg_recv(&ident, router, 0);
    assert(rc >= 0);
    rc = zmq_msg_init_data(&empty, (void*)"", 0, NULL, NULL);
    assert(rc >= 0);
    
    rc = zmq_msg_send(&ident, router, ZMQ_SNDMORE);
    assert(rc >= 0);
    rc = zmq_msg_close(&ident);
    assert(rc >= 0);
    
    rc = zmq_msg_send(&empty, router, 0);
    assert(rc >= 0);
    
    // This close used to fail with Bad Address
    rc = zmq_msg_close(&empty);
    assert(rc >= 0);
    
    close_zero_linger(dealer);
    close_zero_linger(router);
    zmq_ctx_term(ctx);
}
