/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file


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
#include "fq.hpp"
#include "lb.hpp"

namespace zmq
{

    class dealer_t :
        public socket_base_t
    {
    public:

        dealer_t (class ctx_t *parent_, uint32_t tid_);
        ~dealer_t ();

    protected:

        //  Overloads of functions from socket_base_t.
        void xattach_pipe (class pipe_t *pipe_, const blob_t &peer_identity_);
        int xsend (class msg_t *msg_, int flags_);
        int xrecv (class msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();
        void xread_activated (class pipe_t *pipe_);
        void xwrite_activated (class pipe_t *pipe_);
        void xterminated (class pipe_t *pipe_);

    private:

        //  Messages are fair-queued from inbound pipes. And load-balanced to
        //  the outbound pipes.
        fq_t fq;
        lb_t lb;

        dealer_t (const dealer_t&);
        const dealer_t &operator = (const dealer_t&);
    };

}

#endif
