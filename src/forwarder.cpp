/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"

#include "forwarder.hpp"
#include "socket_base.hpp"
#include "err.hpp"

int zmq::forwarder (socket_base_t *insocket_, socket_base_t *outsocket_)
{
    zmq_msg_t msg;
    int rc = zmq_msg_init (&msg);
    errno_assert (rc == 0);

    while (true) {
        insocket_->recv (&msg, 0);
        outsocket_->send (&msg, 0);
    }

    return 0;
}
