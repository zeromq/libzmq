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

#ifndef __ZMQ_GSSAPI_CLIENT_HPP_INCLUDED__
#define __ZMQ_GSSAPI_CLIENT_HPP_INCLUDED__

#ifdef HAVE_LIBGSSAPI_KRB5

#include "gssapi_mechanism_base.hpp"

namespace zmq
{

    class msg_t;

    class gssapi_client_t :
        public gssapi_mechanism_base_t
    {
    public:

        gssapi_client_t (const options_t &options_);
        virtual ~gssapi_client_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual int encode (msg_t *msg_);
        virtual int decode (msg_t *msg_);
        virtual status_t status () const;

    private:

        enum state_t {
            call_next_init,
            send_next_token,
            recv_next_token,
            send_ready,
            recv_ready,
            connected
        };

        //  Human-readable principal name of the service we are connecting to
        char * service_name;

        //  Current FSM state
        state_t state;

        //  Points to either send_tok or recv_tok
        //  during context initialization
        gss_buffer_desc *token_ptr;

        //  The desired underlying mechanism
        gss_OID_set_desc mechs;

        //  True iff client considers the server authenticated
        bool security_context_established;

        int initialize_context ();
        int produce_next_token (msg_t *msg_);
        int process_next_token (msg_t *msg_);
    };

}

#endif

#endif
