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

#ifndef __ZMQ_SUB_INCLUDED__
#define __ZMQ_SUB_INCLUDED__

#include <set>
#include <string>

#include "socket_base.hpp"

namespace zmq
{

    class sub_t : public socket_base_t
    {
    public:

        sub_t (class app_thread_t *parent_);
        ~sub_t ();

        //  Overloads of API functions from socket_base_t.
        int setsockopt (int option_, const void *optval_, size_t optvallen_);
        int recv (struct zmq_msg_t *msg_, int flags_);

    private:

        //  List of all the active subscriptions.
        typedef std::multiset <std::string> subscriptions_t;
        subscriptions_t subscriptions;
    };

}

#endif
