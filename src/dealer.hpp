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

#ifndef __ZMQ_DEALER_HPP_INCLUDED__
#define __ZMQ_DEALER_HPP_INCLUDED__

#include "socket_base.hpp"
#include "session_base.hpp"
#include "fq.hpp"
#include "lb.hpp"

namespace zmq
{

    class ctx_t;
    class msg_t;
    class pipe_t;
    class io_thread_t;
    class socket_base_t;

    class dealer_t :
        public socket_base_t
    {
    public:

        dealer_t (zmq::ctx_t *parent_, uint32_t tid_, int sid);
        ~dealer_t ();

    protected:

        //  Overrides of functions from socket_base_t.
        void xattach_pipe (zmq::pipe_t *pipe_, bool subscribe_to_all_);
        int xsetsockopt (int option_, const void *optval_, size_t optvallen_);
        int xsend (zmq::msg_t *msg_);
        int xrecv (zmq::msg_t *msg_);
        bool xhas_in ();
        bool xhas_out ();
        blob_t get_credential () const;
        void xread_activated (zmq::pipe_t *pipe_);
        void xwrite_activated (zmq::pipe_t *pipe_);
        void xpipe_terminated (zmq::pipe_t *pipe_);

        //  Send and recv - knowing which pipe was used.
        int sendpipe (zmq::msg_t *msg_, zmq::pipe_t **pipe_);
        int recvpipe (zmq::msg_t *msg_, zmq::pipe_t **pipe_);

    private:

        //  Messages are fair-queued from inbound pipes. And load-balanced to
        //  the outbound pipes.
        fq_t fq;
        lb_t lb;

        // if true, send an empty message to every connected router peer
        bool probe_router;

        dealer_t (const dealer_t&);
        const dealer_t &operator = (const dealer_t&);
    };

}

#endif
