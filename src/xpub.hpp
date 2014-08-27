/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_XPUB_HPP_INCLUDED__
#define __ZMQ_XPUB_HPP_INCLUDED__

#include <deque>
#include <string>

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

    class xpub_t :
        public socket_base_t
    {
    public:

        xpub_t (zmq::ctx_t *parent_, uint32_t tid_, int sid_);
        ~xpub_t ();

        //  Implementations of virtual functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_, bool subscribe_to_all_ = false);
        int xsend (zmq::msg_t *msg_);
        bool xhas_out ();
        int xrecv (zmq::msg_t *msg_);
        bool xhas_in ();
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
        void xpipe_terminated (zmq::pipe_t *pipe_);

    private:

        //  Function to be applied to the trie to send all the subsciptions
        //  upstream.
        static void send_unsubscription (unsigned char *data_, size_t size_,
            void *arg_);

        //  Function to be applied to each matching pipes.
        static void mark_as_matching (zmq::pipe_t *pipe_, void *arg_);

        //  List of all subscriptions mapped to corresponding pipes.
        mtrie_t subscriptions;

        //  Distributor of messages holding the list of outbound pipes.
        dist_t dist;

        // If true, send all subscription messages upstream, not just
        // unique ones
        bool verbose;

        //  True if we are in the middle of sending a multi-part message.
        bool more;

        //  Drop messages if HWM reached, otherwise return with EAGAIN
        bool lossy;

        //  List of pending (un)subscriptions, ie. those that were already
        //  applied to the trie, but not yet received by the user.
        typedef std::basic_string <unsigned char> blob_t;
        std::deque <blob_t> pending_data;
        std::deque <unsigned char> pending_flags;

        xpub_t (const xpub_t&);
        const xpub_t &operator = (const xpub_t&);
    };

}

#endif
