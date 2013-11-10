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
#include <zmq.h>
#include <stdio.h>
#include <stdlib.h>

const int no_of_sockets = 2 * 65536;

int main(void)
{
    setup_test_environment();

    void *ctx = zmq_ctx_new();
    zmq_ctx_set(ctx, ZMQ_MAX_SOCKETS, no_of_sockets);
    void *sockets[no_of_sockets];
    
    int sockets_created = 0;

    for ( int i = 0; i < no_of_sockets; ++i )
    {
        sockets[i] = zmq_socket(ctx, ZMQ_PAIR);
        if (sockets[i])
            ++sockets_created;
    }

    assert(sockets_created < no_of_sockets);

    for ( int i = 0; i < no_of_sockets; ++i )
        if (sockets[i])
            zmq_close (sockets[i]);

    zmq_ctx_destroy (ctx);
    return 0;
}
