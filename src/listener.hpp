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

#ifndef __ZMQ_LISTENER_HPP_INCLUDED__
#define __ZMQ_LISTENER_HPP_INCLUDED__

#include <map>
#include <vector>
#include <string>

#include "io_object.hpp"
#include "tcp_listener.hpp"
#include "i_poller.hpp"
#include "i_poll_events.hpp"
#include "stdint.hpp"

namespace zmq
{

    class listener_t : public io_object_t, public i_poll_events
    {
    public:

        listener_t (class io_thread_t *thread_, const char *addr_,
            class session_t *peer_, bool has_in_, bool has_out_,
            uint64_t taskset_);

        void terminate ();
        void shutdown ();

        //  This function is called by session stub once the identity
        //  is retrieved from the incoming connection.
        void got_identity (class session_stub_t *session_stub_,
            const char *identity_);

        void process_reg (class simple_semaphore_t *smph_);
        void process_unreg (class simple_semaphore_t *smph_);

        //  i_poll_events implementation.
        void in_event ();
        void out_event ();
        void timer_event ();

    private:

        ~listener_t ();

        struct i_poller *poller;

        //  Handle corresponding to the listening socket.
        handle_t handle;

        //  Actual listening socket.
        tcp_listener_t tcp_listener;

        //  Address to bind to.
        std::string addr;

        //  Peer session. All the newly created connections should bind to
        //  this session.
        session_t *peer;

        //  Taskset specifies which I/O threads are to be use to handle
        //  newly created connections (0 = all).
        uint64_t taskset;

        //  Sessions created by this listener are stored in this map. They are
        //  indexed by peer identities so that the same peer connects to the
        //  same session after reconnection.
        //  NB: Sessions are destroyed from other place and possibly later on,
        //  so no need to care about them during listener object termination.
        typedef std::map <std::string, class session_t*> sessions_t;
        sessions_t sessions;

        //  List of engines (bound to temorary session stubs) that we haven't
        //  retrieved the identity from so far.
        typedef std::vector <class session_stub_t*> session_stubs_t;
        session_stubs_t session_stubs;

        //  If true, create inbound pipe when binding new connection
        //  to the peer.
        bool has_in;

        //  If true, create outbound pipe when binding new connection
        //  to the peer.
        bool has_out;      

        listener_t (const listener_t&);
        void operator = (const listener_t&);
    };

}

#endif
