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

static void do_bind_and_verify (void *s, const char *endpoint)
{
    int rc = zmq_bind (s, endpoint);
    assert (rc == 0);
    char reported [255];
    size_t size = 255;
    rc = zmq_getsockopt (s, ZMQ_LAST_ENDPOINT, reported, &size);
    assert (rc == 0 && strcmp (reported, endpoint) == 0);
}

int main (void)
{
    setup_test_environment();
    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_ROUTER);
    assert (sb);
    int val = 0;
    int rc = zmq_setsockopt (sb, ZMQ_LINGER, &val, sizeof (val));
    assert (rc == 0);

    do_bind_and_verify (sb, "tcp://127.0.0.1:5560");
    do_bind_and_verify (sb, "tcp://127.0.0.1:5561");

    rc = zmq_close (sb);
    assert (rc == 0);
    
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}

