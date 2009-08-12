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

#ifndef __ZMQ_OWNED_HPP_INCLUDED__
#define __ZMQ_OWNED_HPP_INCLUDED__

#include "object.hpp"

namespace zmq
{

    //  Base class for objects owned by individual sockets. Handles
    //  initialisation and destruction of such objects.

    class owned_t : public object_t
    {
    public:

        //  The object will live in parent's thread, however, its lifetime
        //  will be managed by its owner socket.
        owned_t (object_t *parent_, object_t *owner_);

    protected:

        //  Ask owner socket to terminate this object.
        void term ();

        //  Derived object destroys owned_t. No point in allowing others to
        //  invoke the destructor. At the same time, it has to be virtual so
        //  that generic owned_t deallocation mechanism destroys specific type
        //  of the owned object correctly.
        virtual ~owned_t ();

        //  Handlers for incoming commands. It's vital that every I/O object
        //  invokes io_object_t::process_plug at the end of it's own plug
        //  handler.
        void process_plug ();

        //  io_object_t defines a new handler used to disconnect the object
        //  from the poller object. Implement the handlen in the derived
        //  classes to ensure sane cleanup.
        virtual void process_unplug () = 0;

        //  Socket owning this object. It is responsible for destroying
        //  it when it's being closed.
        object_t *owner;

    private:

        //  Handlers for incoming commands.
        void process_term ();

        //  Set to true when object is plugged in.
        bool plugged_in;

        //  Set to true when object was terminated before it was plugged in.
        //  In such case destruction is delayed till 'plug' command arrives.
        bool terminated;

        owned_t (const owned_t&);
        void operator = (const owned_t&);
    };

}

#endif
