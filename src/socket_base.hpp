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

#include "object.hpp"
#include "options.hpp"
#include "stdint.hpp"

namespace zmq
{

    class socket_base_t : public object_t
    {
    public:

        socket_base_t (class app_thread_t *parent_);
        ~socket_base_t ();

        //  Interface for communication with the API layer.
        virtual int setsockopt (int option_, void *optval_, size_t optvallen_);
        virtual int bind (const char *addr_);
        virtual int connect (const char *addr_);
        virtual int subscribe (const char *criteria_);
        virtual int send (struct zmq_msg *msg_, int flags_);
        virtual int flush ();
        virtual int recv (struct zmq_msg *msg_, int flags_);
        virtual int close ();

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
        options_t options;

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
