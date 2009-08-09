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

#ifndef __ZMQ_SOCKET_BASE_HPP_INCLUDED__
#define __ZMQ_SOCKET_BASE_HPP_INCLUDED__

#include <set>
#include <string>

#include "i_api.hpp"
#include "object.hpp"
#include "stdint.hpp"

namespace zmq
{

    class socket_base_t : public object_t, public i_api
    {
    public:

        socket_base_t (class app_thread_t *parent_);
        ~socket_base_t ();

        //  i_api interface implementation.
        int setsockopt (int option_, void *optval_, size_t optvallen_);
        int bind (const char *addr_);
        int connect (const char *addr_);
        int subscribe (const char *criteria_);
        int send (struct zmq_msg *msg_, int flags_);
        int flush ();
        int recv (struct zmq_msg *msg_, int flags_);
        int close ();

    private:

        //  Handlers for incoming commands.
        void process_own (object_t *object_);
        void process_term_req (object_t *object_);
        void process_term_ack ();

        //  List of all I/O objects owned by this socket. The socket is
        //  responsible for deallocating them before it quits.
        typedef std::set <object_t*> io_objects_t;
        io_objects_t io_objects;

        //  Number of I/O objects that were already asked to terminate
        //  but haven't acknowledged it yet.
        int pending_term_acks;

        //  Application thread the socket lives in.
        class app_thread_t *app_thread;

        //  Socket options.
        int64_t hwm;
        int64_t lwm;
        int64_t swap;
        uint64_t mask;
        uint64_t affinity;
        std::string session_id;

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
