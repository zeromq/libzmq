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

/*
   This program tests that multiple connections to the same endpoint are (silently) ignored
   when SUB binds and PUB connects, as per https://github.com/zeromq/libzmq/pull/2879

*/

#include <zmq.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "testutil.hpp"

int connectTest(int connects)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (pub);

    void *sub = zmq_socket (ctx, ZMQ_SUB);
    assert (sub);

    int rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);

    rc = zmq_bind (sub, "tcp://127.0.0.1:5555");
    assert (rc >= 0);

    for (int i = 0; i < connects; ++i) {
       rc = zmq_connect (pub, "tcp://127.0.0.1:5555");
       assert (rc >= 0);
    }

    // because sub binds and pub connects ...
    // https://github.com/zeromq/libzmq/issues/2267
    zmq_pollitem_t pollitems [] = { { sub, 0, ZMQ_POLLIN, 0 } };
    zmq_poll (pollitems, 1, 1);

    rc = zmq_send (pub, "TEST", 5, 0);
    assert (rc == 5);
    char buffer [5];

    // should only get a single message
    rc = zmq_recv (sub, buffer, 5, 0);
    assert (rc == 5);
    assert (strcmp (buffer, "TEST") == 0);
    //
    rc = zmq_recv (sub, buffer, 5, ZMQ_DONTWAIT);
    assert (rc == -1);
    assert (errno == EAGAIN);

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return rc;
}


int main (void)
{
    setup_test_environment();

    int rc = connectTest(1);
    assert (rc == 0);

    rc = connectTest(2);
    assert (rc == 0);

    rc = connectTest(10);
    assert (rc == 0);

    return 0;
}
