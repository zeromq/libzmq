/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

    void *radio = zmq_socket (ctx, ZMQ_RADIO);
    void *dish = zmq_socket (ctx, ZMQ_DISH);

    int rc = zmq_bind (radio, "inproc://test-radio-dish");
    assert (rc == 0);

    //  Leaving a group which we didn't join
    rc = zmq_leave (dish, "World");
    assert (rc == -1);

    //  Joining too long group
    char too_long_group[ZMQ_GROUP_MAX_LENGTH + 2];
    for (int index = 0; index < ZMQ_GROUP_MAX_LENGTH + 2; index++)
        too_long_group[index] = 'A';
    too_long_group[ZMQ_GROUP_MAX_LENGTH + 1] = '\0';
    rc = zmq_join (dish, too_long_group);
    assert (rc == -1);

    // Joining
    rc = zmq_join (dish, "World");
    assert (rc == 0);

    // Duplicate Joining
    rc = zmq_join (dish, "World");
    assert (rc == -1);

    // Connecting
    rc = zmq_connect (dish, "inproc://test-radio-dish");
    assert (rc == 0);

    zmq_sleep (1);

    //  This is not going to be sent as dish only subscribe to "World"
    rc = zmq_send (radio, "Hello\0Message", 13, 0);
    assert (rc == 13);

    //  This is going to be sent to the dish
    rc = zmq_send (radio, "World\0Message", 13, 0);
    assert (rc == 13);

    char* data = (char*) malloc (sizeof(char) * 13);

    rc = zmq_recv (dish, data, 13, 0);
    assert (rc == 13);
    assert (strcmp (data, "World") == 0);

    //  Join group during connection optvallen
    rc = zmq_join (dish, "Hello");
    assert (rc == 0);

    zmq_sleep (1);

    //  This should arrive now as we joined the group
    rc = zmq_send (radio, "Hello\0Message", 13, 0);
    assert (rc == 13);

    rc = zmq_recv (dish, data, 13, 0);
    assert (rc == 13);
    assert (strcmp (data, "Hello") == 0);

    //  Leaving group
    rc = zmq_leave (dish, "Hello");
    assert (rc == 0);

    zmq_sleep (1);

    //  This is not going to be sent as dish only subscribe to "World"
    rc = zmq_send (radio, "Hello\0Message", 13, 0);
    assert (rc == 13);

    //  This is going to be sent to the dish
    rc = zmq_send (radio, "World\0Message", 13, 0);
    assert (rc == 13);

    rc = zmq_recv (dish, data, 13, 0);
    assert (rc == 13);
    assert (strcmp (data, "World") == 0);

    free (data);

    rc = zmq_close (dish);
    assert (rc == 0);

    rc = zmq_close (radio);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
