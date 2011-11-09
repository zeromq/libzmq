/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
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

#ifndef __ZMQ_REQ_HPP_INCLUDED__
#define __ZMQ_REQ_HPP_INCLUDED__

#include "xreq.hpp"
#include "stdint.hpp"

namespace zmq
{

    class ctx_t;
    class msg_t;
    class io_thread_t;
    class socket_base_t;

    class req_t : public xreq_t
    {
    public:

        req_t (zmq::ctx_t *parent_, uint32_t tid_);
        ~req_t ();

        //  Overloads of functions from socket_base_t.
        int xsend (zmq::msg_t *msg_, int flags_);
        int xrecv (zmq::msg_t *msg_, int flags_);
        bool xhas_in ();
        bool xhas_out ();

    private:

        //  If true, request was already sent and reply wasn't received yet or
        //  was raceived partially.
        bool receiving_reply;

        //  If true, we are starting to send/recv a message. The first part
        //  of the message must be empty message part (backtrace stack bottom).
        bool message_begins;

        req_t (const req_t&);
        const req_t &operator = (const req_t&);
    };

    class req_session_t : public xreq_session_t
    {
    public:

        req_session_t (zmq::io_thread_t *io_thread_, bool connect_,
            zmq::socket_base_t *socket_, const options_t &options_,
            const char *protocol_, const char *address_);
        ~req_session_t ();

        //  Overloads of the functions from session_base_t.
        int write (msg_t *msg_);

    private:

        enum {
            identity,
            bottom,
            body
        } state;

        req_session_t (const req_session_t&);
        const req_session_t &operator = (const req_session_t&);
    };

}

#endif
