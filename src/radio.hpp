/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_RADIO_HPP_INCLUDED__
#define __ZMQ_RADIO_HPP_INCLUDED__

#include <map>
#include <string>
#include <vector>

#include "socket_base.hpp"
#include "session_base.hpp"
#include "mtrie.hpp"
#include "array.hpp"
#include "dist.hpp"

namespace zmq
{

    class ctx_t;
    class msg_t;
    class pipe_t;
    class io_thread_t;

    class radio_t :
        public socket_base_t
    {
    public:

        radio_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
        ~radio_t ();

        //  Implementations of virtual functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_, bool subscribe_to_all_ = false);
        int xsend (zmq::msg_t *msg_);
        bool xhas_out ();
        int xrecv (zmq::msg_t *msg_);
        bool xhas_in ();
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        void xpipe_terminated (zmq::pipe_t *pipe_);

    private:
        //  List of all subscriptions mapped to corresponding pipes.
        typedef std::multimap<std::string, pipe_t*> subscriptions_t;
        subscriptions_t subscriptions;

        //  List of udp pipes
        typedef std::vector<pipe_t*> udp_pipes_t;
        udp_pipes_t udp_pipes;

        //  Distributor of messages holding the list of outbound pipes.
        dist_t dist;

        radio_t (const radio_t&);
        const radio_t &operator = (const radio_t&);
    };

    class radio_session_t : public session_base_t
    {
    public:

        radio_session_t (zmq::io_thread_t *io_thread_, bool connect_,
            zmq::socket_base_t *socket_, const options_t &options_,
            address_t *addr_);
        ~radio_session_t ();

        //  Overrides of the functions from session_base_t.
        int push_msg (msg_t *msg_);
        int pull_msg (msg_t *msg_);
        void reset ();
    private:

        enum {
            group,
            body
        } state;

        msg_t pending_msg;

        radio_session_t (const radio_session_t&);
        const radio_session_t &operator = (const radio_session_t&);
    };
}

#endif
