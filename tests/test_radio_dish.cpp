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

int msg_send (zmq_msg_t *msg_, void *s_, const char* group_, const char* body_)
{
    int rc = zmq_msg_init_size (msg_, strlen (body_));
    if (rc != 0)
        return rc;

    memcpy (zmq_msg_data (msg_), body_, strlen (body_));

    rc = zmq_msg_set_group (msg_, group_);
    if (rc != 0) {
        zmq_msg_close (msg_);
        return rc;
    }

    rc = zmq_msg_send (msg_, s_, 0);

    zmq_msg_close (msg_);

    return rc;
}

int msg_recv_cmp (zmq_msg_t *msg_, void *s_, const char* group_, const char* body_)
{
    int rc = zmq_msg_init (msg_);
    if (rc != 0)
        return -1;

    int recv_rc = zmq_msg_recv (msg_, s_, 0);
    if (recv_rc == -1)
        return -1;

    if (strcmp (zmq_msg_group (msg_), group_) != 0)
    {
        zmq_msg_close (msg_);
        return -1;
    }

    char * body = (char*) malloc (sizeof(char) * (zmq_msg_size (msg_) + 1));
    memcpy (body, zmq_msg_data (msg_), zmq_msg_size (msg_));
    body [zmq_msg_size (msg_)] = '\0';

    if (strcmp (body, body_) != 0)
    {
        zmq_msg_close (msg_);
        return -1;
    }

    zmq_msg_close (msg_);
    free(body);
    return recv_rc;
}

int main (void)
{
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *radio = zmq_socket (ctx, ZMQ_RADIO);
    void *dish = zmq_socket (ctx, ZMQ_DISH);

    int rc = zmq_bind (radio, "tcp://127.0.0.1:5556");
    assert (rc == 0);

    //  Leaving a group which we didn't join
    rc = zmq_leave (dish, "Movies");
    assert (rc == -1);

    //  Joining too long group
    char too_long_group[ZMQ_GROUP_MAX_LENGTH + 2];
    for (int index = 0; index < ZMQ_GROUP_MAX_LENGTH + 2; index++)
        too_long_group[index] = 'A';
    too_long_group[ZMQ_GROUP_MAX_LENGTH + 1] = '\0';
    rc = zmq_join (dish, too_long_group);
    assert (rc == -1);

    // Joining
    rc = zmq_join (dish, "Movies");
    assert (rc == 0);

    // Duplicate Joining
    rc = zmq_join (dish, "Movies");
    assert (rc == -1);

    // Connecting
    rc = zmq_connect (dish, "tcp://127.0.0.1:5556");
    assert (rc == 0);

    msleep (SETTLE_TIME);

    zmq_msg_t msg;

    //  This is not going to be sent as dish only subscribe to "Movies"
    rc = msg_send (&msg, radio, "TV", "Friends");
    assert (rc == 7);

    //  This is going to be sent to the dish
    rc = msg_send (&msg, radio, "Movies", "Godfather");
    assert (rc == 9);

    //  Check the correct message arrived
    rc = msg_recv_cmp (&msg, dish, "Movies", "Godfather");
    assert (rc == 9);

    //  Join group during connection optvallen
    rc = zmq_join (dish, "TV");
    assert (rc == 0);

    zmq_sleep (1);

    //  This should arrive now as we joined the group
    rc = msg_send (&msg, radio, "TV", "Friends");
    assert (rc == 7);

    //  Check the correct message arrived
    rc = msg_recv_cmp (&msg, dish, "TV", "Friends");
    assert (rc == 7);

    //  Leaving groupr
    rc = zmq_leave (dish, "TV");
    assert (rc == 0);

    zmq_sleep (1);

    //  This is not going to be sent as dish only subscribe to "Movies"
    rc = msg_send (&msg, radio, "TV", "Friends");
    assert (rc == 7);

    //  This is going to be sent to the dish
    rc = msg_send (&msg, radio, "Movies", "Godfather");
    assert (rc == 9);

    // test zmq_poll with dish
    zmq_pollitem_t items [] = {
        { radio, 0, ZMQ_POLLIN, 0 }, // read publications
        { dish, 0, ZMQ_POLLIN, 0 }, // read subscriptions
    };
    rc = zmq_poll(items, 2, 2000);
    assert (rc == 1);
    assert (items[1].revents == ZMQ_POLLIN);

    //  Check the correct message arrived
    rc = msg_recv_cmp (&msg, dish, "Movies", "Godfather");
    assert (rc == 9);

    rc = zmq_close (dish);
    assert (rc == 0);

    rc = zmq_close (radio);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}
