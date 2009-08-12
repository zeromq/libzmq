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

#ifndef __ZMQ_SESSION_HPP_INCLUDED__
#define __ZMQ_SESSION_HPP_INCLUDED__

#include "i_inout.hpp"
#include "owned.hpp"

namespace zmq
{

    class session_t : public owned_t, public i_inout
    {
    public:

        session_t (object_t *parent_, object_t *owner_,
            class zmq_engine_t *engine_);

    private:

        ~session_t ();

        //  i_inout interface implementation.
        bool read (::zmq_msg *msg_);
        bool write (::zmq_msg *msg_);
        void flush ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();

        class zmq_engine_t *engine;

        session_t (const session_t&);
        void operator = (const session_t&);
    };

}

#endif
