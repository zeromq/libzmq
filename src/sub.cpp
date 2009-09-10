/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include "../c/zmq.h"

#include "sub.hpp"
#include "err.hpp"

zmq::sub_t::sub_t (class app_thread_t *parent_) :
    socket_base_t (parent_)
{
}

zmq::sub_t::~sub_t ()
{
}

int zmq::sub_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (option_ == ZMQ_SUBSCRIBE) {
        std::string subscription ((const char*) optval_, optvallen_);
        subscriptions.insert (subscription);
        return 0;
    }
    
    if (option_ == ZMQ_UNSUBSCRIBE) {
        std::string subscription ((const char*) optval_, optvallen_);
        subscriptions_t::iterator it = subscriptions.find (subscription);
        if (it == subscriptions.end ()) {
            errno = EINVAL;
            return -1;
        }
        subscriptions.erase (it);
        return 0;
    }

    return socket_base_t::setsockopt (option_, optval_, optvallen_);
}

int zmq::sub_t::recv (struct zmq_msg_t *msg_, int flags_)
{
    while (true) {

        //  Get a message.
        int rc = socket_base_t::recv (msg_, flags_);

        //  If there's no message available, return immediately.
        if (rc != 0 && errno == EAGAIN)
            return -1;

        //  Check the message format.
        //  TODO: We should either ignore the message or drop the connection
        //  if the message doesn't conform with the expected format.
        unsigned char *data = (unsigned char*) zmq_msg_data (msg_);
        zmq_assert (*data <= zmq_msg_size (msg_) - 1);

        //  Check whether the message matches at least one subscription.
        std::string topic ((const char*) (data + 1), *data);
        subscriptions_t::iterator it = subscriptions.find (topic);
        if (it != subscriptions.end ())
            break;
    }

    return 0;
}
