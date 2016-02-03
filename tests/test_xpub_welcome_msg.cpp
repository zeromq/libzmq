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

int main (void)
{
    setup_test_environment();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Create a publisher
    void *pub = zmq_socket (ctx, ZMQ_XPUB);
    assert (pub);
    int rc = zmq_bind (pub, "inproc://soname");
    assert (rc == 0);

    //  set pub socket options
    rc = zmq_setsockopt(pub, ZMQ_XPUB_WELCOME_MSG, "W", 1);
    assert (rc == 0);

    //  Create a subscriber
    void *sub = zmq_socket (ctx, ZMQ_SUB);

    // Subscribe to the welcome message
    rc = zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "W", 1);
    assert(rc == 0);

    assert (sub);
    rc = zmq_connect (sub, "inproc://soname");
    assert (rc == 0);

    char buffer[2];

    // Receive the welcome subscription
    rc = zmq_recv(pub, buffer, 2, 0);
    assert(rc == 2);
    assert(buffer[0] == 1);
    assert(buffer[1] == 'W');

    // Receive the welcome message
    rc = zmq_recv(sub, buffer, 1, 0);
    assert(rc == 1);
    assert(buffer[0] == 'W');

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
