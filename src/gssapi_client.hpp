/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_GSSAPI_CLIENT_HPP_INCLUDED__
#define __ZMQ_GSSAPI_CLIENT_HPP_INCLUDED__

#include "gssapi_mechanism_base.hpp"
#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;

    class gssapi_client_t :
        public gssapi_mechanism_base_t,
        public mechanism_t
    {
    public:

        gssapi_client_t (const options_t &options_);
        virtual ~gssapi_client_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual bool is_handshake_complete () const;

    private:
 
        enum state_t {
            sending_hello,
            waiting_for_welcome,
            sending_initiate,
            sending_token,
            waiting_for_token,
            waiting_for_ready,
            ready
        };

        state_t state;

        int produce_hello (msg_t *msg_) const;
        int produce_initiate (msg_t *msg_) const;

        int process_welcome (msg_t *msg);
        int process_ready (msg_t *msg_);
    };

}

#endif
