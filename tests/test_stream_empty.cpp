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

int main (void) {
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    
    void *stream = zmq_socket (ctx, ZMQ_STREAM);
    assert (stream);
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    assert (dealer);
    
    int rc = zmq_bind (stream, "tcp://127.0.0.1:5555");
    assert (rc >= 0);
    rc = zmq_connect (dealer, "tcp://127.0.0.1:5555");
    assert (rc >= 0);
    zmq_send (dealer, "", 0, 0);
    
    zmq_msg_t ident, empty;
    zmq_msg_init (&ident);
    rc = zmq_msg_recv (&ident, stream, 0);
    assert (rc >= 0);
    rc = zmq_msg_init_data (&empty, (void *) "", 0, NULL, NULL);
    assert (rc >= 0);
    
    rc = zmq_msg_send (&ident, stream, ZMQ_SNDMORE);
    assert (rc >= 0);
    rc = zmq_msg_close (&ident);
    assert (rc >= 0);
    
    rc = zmq_msg_send (&empty, stream, 0);
    assert (rc >= 0);
    
    //  This close used to fail with Bad Address
    rc = zmq_msg_close (&empty);
    assert (rc >= 0);
    
    close_zero_linger (dealer);
    close_zero_linger (stream);
    zmq_ctx_term (ctx);
}
