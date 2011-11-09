/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_XSUB_HPP_INCLUDED__
#define __ZMQ_XSUB_HPP_INCLUDED__

#include "socket_base.hpp"
#include "session_base.hpp"
#include "dist.hpp"
#include "fq.hpp"
#include "trie.hpp"

namespace zmq
{

    class ctx_t;
    class pipe_t;
    class io_thread_t;

    class xsub_t :
        public socket_base_t
    {
    public:

        xsub_t (zmq::ctx_t *parent_, uint32_t tid_);
        ~xsub_t ();

    protected:

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_);
        int xsend (zmq::msg_t *msg_, int flags_);
        bool xhas_out ();
        int xrecv (zmq::msg_t *msg_, int flags_);
        bool xhas_in ();
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        void xhiccuped (pipe_t *pipe_);
        void xterminated (zmq::pipe_t *pipe_);

    private:

        //  Check whether the message matches at least one subscription.
        bool match (zmq::msg_t *msg_);

        //  Function to be applied to the trie to send all the subsciptions
        //  upstream.
        static void send_subscription (unsigned char *data_, size_t size_,
            void *arg_);

        //  Fair queueing object for inbound pipes.
        fq_t fq;

        //  Object for distributing the subscriptions upstream.
        dist_t dist;

        //  The repository of subscriptions.
        trie_t subscriptions;

        //  If true, 'message' contains a matching message to return on the
        //  next recv call.
        bool has_message;
        msg_t message;

        //  If true, part of a multipart message was already received, but
        //  there are following parts still waiting.
        bool more;

        xsub_t (const xsub_t&);
        const xsub_t &operator = (const xsub_t&);
    };

    class xsub_session_t : public session_base_t
    {
    public:

        xsub_session_t (class io_thread_t *io_thread_, bool connect_,
            socket_base_t *socket_, const options_t &options_,
            const char *protocol_, const char *address_);
        ~xsub_session_t ();

    private:

        xsub_session_t (const xsub_session_t&);
        const xsub_session_t &operator = (const xsub_session_t&);
    };

}

#endif

