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

#ifndef __ZMQ_APP_THREAD_HPP_INCLUDED__
#define __ZMQ_APP_THREAD_HPP_INCLUDED__

#include <vector>

#include "stdint.hpp"
#include "object.hpp"
#include "yarray.hpp"
#include "signaler.hpp"

namespace zmq
{

    class app_thread_t : public object_t
    {
    public:

        app_thread_t (class ctx_t *ctx_, uint32_t thread_slot_);

        ~app_thread_t ();

        //  Interrupt blocking call if the app thread is stuck in one.
        //  This function is is called from a different thread!
        void stop ();

        //  Returns signaler associated with this application thread.
        signaler_t *get_signaler ();

        //  Processes commands sent to this thread (if any). If 'block' is
        //  set to true, returns only after at least one command was processed.
        //  If throttle argument is true, commands are processed at most once
        //  in a predefined time period. The function returns false is the
        //  associated context was terminated, true otherwise.
        bool process_commands (bool block_, bool throttle_);

        //  Create a socket of a specified type.
        class socket_base_t *create_socket (int type_);

        //  Unregister the socket from the app_thread (called by socket itself).
        void remove_socket (class socket_base_t *socket_);

        //  Returns true is the associated context was already terminated.
        bool is_terminated ();

    private:

        //  Command handlers.
        void process_stop ();

        //  All the sockets created from this application thread.
        typedef yarray_t <socket_base_t> sockets_t;
        sockets_t sockets;

        //  App thread's signaler object.
        signaler_t signaler;

        //  Timestamp of when commands were processed the last time.
        uint64_t last_processing_time;

        //  If true, 'stop' command was already received.
        bool terminated;

        app_thread_t (const app_thread_t&);
        void operator = (const app_thread_t&);
    };

}

#endif
