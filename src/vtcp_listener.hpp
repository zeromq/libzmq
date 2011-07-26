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

#ifndef __ZMQ_VTCP_LISTENER_HPP_INCLUDED__
#define __ZMQ_VTCP_LISTENER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_VTCP

#include "own.hpp"
#include "io_object.hpp"
#include "fd.hpp"

namespace zmq
{

    class vtcp_listener_t : public own_t, public io_object_t
    {
    public:

        vtcp_listener_t (class io_thread_t *io_thread_,
            class socket_base_t *socket_, class options_t &options_);
        ~vtcp_listener_t ();

        int set_address (const char *addr_);

    private:

        //  Handlers for incoming commands.
        void process_plug ();
        void process_term (int linger_);

        //  Handlers for I/O events.
        void in_event ();

        //  VTCP listener socket.
        fd_t s;

        //  Handle corresponding to the listening socket.
        handle_t handle;

        //  Socket the listerner belongs to.
        class socket_base_t *socket;

        vtcp_listener_t (const vtcp_listener_t&);
        const vtcp_listener_t &operator = (const vtcp_listener_t&);
    };

}

#endif

#endif
