/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#ifndef __ZMQ_TEST_TESTUTIL_HPP_INCLUDED__
#define __ZMQ_TEST_TESTUTIL_HPP_INCLUDED__

#include <assert.h>
#include <string.h>

#include "../include/zmq.h"

inline void bounce (void *sb, void *sc)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";

    //  Send the message.
    zmq_msg_t msg1;
    int rc = zmq_msg_init_size (&msg1, 32);
    memcpy (zmq_msg_data (&msg1), content, 32);
    rc = zmq_send (sc, &msg1, 0);
    assert (rc == 0);
    rc = zmq_msg_close (&msg1);
    assert (rc == 0);

    //  Bounce the message back.
    zmq_msg_t msg2;
    rc = zmq_msg_init (&msg2);
    assert (rc == 0);
    rc = zmq_recv (sb, &msg2, 0);
    assert (rc == 0);
    rc = zmq_send (sb, &msg2, 0);
    assert (rc == 0);
    rc = zmq_msg_close (&msg2);
    assert (rc == 0);

    //  Receive the bounced message.
    zmq_msg_t msg3;
    rc = zmq_msg_init (&msg3);
    assert (rc == 0);
    rc = zmq_recv (sc, &msg3, 0);
    assert (rc == 0);

    //  Check whether the message is still the same.
    assert (zmq_msg_size (&msg3) == 32);
    assert (memcmp (zmq_msg_data (&msg3), content, 32) == 0);

    rc = zmq_msg_close (&msg3);
    assert (rc == 0);
}


#endif
