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
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *scatter = zmq_socket (ctx, ZMQ_SCATTER);
    void *gather = zmq_socket (ctx, ZMQ_GATHER);
    void *gather2 = zmq_socket (ctx, ZMQ_GATHER);    

    int rc = zmq_bind (scatter, "inproc://test-scatter-gather");
    assert (rc == 0);

    rc = zmq_connect (gather, "inproc://test-scatter-gather");
    assert (rc == 0);

    rc = zmq_connect (gather2, "inproc://test-scatter-gather");
    assert (rc == 0);

    //  Should fail, multipart is not supported
    rc = s_sendmore (scatter, "1");
    assert (rc == -1);

    rc = s_send (scatter, "1");
    assert (rc == 1);

    rc = s_send (scatter, "2");
    assert (rc == 1);

    char* message = s_recv (gather);
    assert (message);
    assert (streq(message, "1"));
    free(message);

    message = s_recv (gather2);
    assert (message);
    assert (streq(message, "2"));
    free(message);

    rc = zmq_close (scatter);
    assert (rc == 0);

    rc = zmq_close (gather);
    assert (rc == 0);

    rc = zmq_close (gather2);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
