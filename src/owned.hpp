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

#ifndef __ZMQ_OWNED_HPP_INCLUDED__
#define __ZMQ_OWNED_HPP_INCLUDED__

#include "socket_base.hpp"
#include "atomic_counter.hpp"
#include "stdint.hpp"

namespace zmq
{

    //  Base class for objects owned by individual sockets. Handles
    //  initialisation and destruction of such objects.

    class owned_t : public object_t
    {
    public:

        //  The object will live in parent's thread, however, its lifetime
        //  will be managed by its owner socket.
        owned_t (object_t *parent_, socket_base_t *owner_);

        //  When another owned object wants to send command to this object
        //  it calls this function to let it know it should not shut down
        //  before the command is delivered.
        void inc_seqnum ();

    protected:

        //  Ask owner socket to terminate this object.
        void term ();

        //  Derived object destroys owned_t. No point in allowing others to
        //  invoke the destructor. At the same time, it has to be virtual so
        //  that generic owned_t deallocation mechanism destroys specific type
        //  of the owned object correctly.
        virtual ~owned_t ();

        //  io_object_t defines a new handler used to disconnect the object
        //  from the poller object. Implement the handlen in the derived
        //  classes to ensure sane cleanup.
        virtual void process_unplug () = 0;

        //  Socket owning this object. When the socket is being closed it's
        //  responsible for shutting down this object.
        socket_base_t *owner;

    private:

        //  Handlers for incoming commands.
        void process_term ();
        void process_seqnum ();

        void finalise ();

        //  Sequence number of the last command sent to this object.
        atomic_counter_t sent_seqnum;

        //  Sequence number of the last command processed by this object.
        uint64_t processed_seqnum;

        //  If true, the object is already shutting down.
        bool shutting_down;

        owned_t (const owned_t&);
        void operator = (const owned_t&);
    };

}

#endif
