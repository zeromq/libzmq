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

#ifndef __ZMQ_ZMQ_CONNECTER_HPP_INCLUDED__
#define __ZMQ_ZMQ_CONNECTER_HPP_INCLUDED__

#include <string>

#include "owned.hpp"
#include "io_object.hpp"
#include "tcp_connecter.hpp"
#include "options.hpp"
#include "stdint.hpp"

namespace zmq
{

    class zmq_connecter_t : public owned_t, public io_object_t
    {
    public:

        zmq_connecter_t (class io_thread_t *parent_, socket_base_t *owner_,
            const options_t &options_, uint64_t session_ordinal_, bool wait_);
        ~zmq_connecter_t ();

        //  Set address to connect to.
        int set_address (const char *protocol_, const char *address_);

    private:

        //  Handlers for incoming commands.
        void process_plug ();
        void process_unplug ();

        //  Handlers for I/O events.
        void in_event ();
        void out_event ();
        void timer_event ();

        //  Internal function to start the actual connection establishment.
        void start_connecting ();

        //  Actual connecting socket.
        tcp_connecter_t tcp_connecter;

        //  Handle corresponding to the listening socket.
        handle_t handle;

        //  If true file descriptor is registered with the poller and 'handle'
        //  contains valid value.
        bool handle_valid;

        //  If true, connecter is waiting a while before trying to connect.
        bool wait;

        //  Ordinal of the session to attach to.
        uint64_t session_ordinal;

        //  Associated socket options.
        options_t options;

        //  Protocol and address to connect to.
        std::string protocol;
        std::string address;

        zmq_connecter_t (const zmq_connecter_t&);
        void operator = (const zmq_connecter_t&);
    };

}

#endif
