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

#ifndef __ZMQ_ZMQ_LISTENER_INIT_HPP_INCLUDED__
#define __ZMQ_ZMQ_LISTENER_INIT_HPP_INCLUDED__

#include <string>

#include "i_inout.hpp"
#include "owned.hpp"
#include "zmq_engine.hpp"
#include "stdint.hpp"
#include "fd.hpp"
#include "options.hpp"

namespace zmq
{

    //  The class handles initialisation phase of native 0MQ wire-level
    //  protocol on the listening side of the connection.

    class zmq_listener_init_t : public owned_t, public i_inout
    {
    public:

        zmq_listener_init_t (class io_thread_t *parent_, socket_base_t *owner_,
            fd_t fd_, const options_t &options);
        ~zmq_listener_init_t ();

    private:

        //  i_inout interface implementation.
        bool read (::zmq_msg_t *msg_);
        bool write (::zmq_msg_t *msg_);
        void flush ();
        void detach (owned_t *reconnecter_);
        class io_thread_t *get_io_thread ();
        class socket_base_t *get_owner ();
        const char *get_session_name ();

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();

        //  Engine is created by zmq_listener_init_t object. Once the
        //  initialisation phase is over it is passed to a session object,
        //  possibly running in a different I/O thread.
        zmq_engine_t *engine;

        //  Associated socket options.
        options_t options;

        //  Indetity on the other end of the connection.
        bool has_peer_identity;
        std::string peer_identity;

        zmq_listener_init_t (const zmq_listener_init_t&);
        void operator = (const zmq_listener_init_t&);
    };

}

#endif
