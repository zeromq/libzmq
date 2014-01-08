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

#ifndef __ZMQ_REP_HPP_INCLUDED__
#define __ZMQ_REP_HPP_INCLUDED__

#include "router.hpp"

namespace zmq
{

    class ctx_t;
    class msg_t;
    class io_thread_t;
    class socket_base_t;

    class rep_t : public router_t
    {
    public:

        rep_t (zmq::ctx_t *parent_, uint32_t tid_, int sid);
        ~rep_t ();

        //  Overrides of functions from socket_base_t.
        int xsend (zmq::msg_t *msg_);
        int xrecv (zmq::msg_t *msg_);
        bool xhas_in ();
        bool xhas_out ();

    private:

        //  If true, we are in process of sending the reply. If false we are
        //  in process of receiving a request.
        bool sending_reply;

        //  If true, we are starting to receive a request. The beginning
        //  of the request is the backtrace stack.
        bool request_begins;

        rep_t (const rep_t&);
        const rep_t &operator = (const rep_t&);

    };

}

#endif
