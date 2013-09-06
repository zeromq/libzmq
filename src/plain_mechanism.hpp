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

#ifndef __ZMQ_PLAIN_MECHANISM_HPP_INCLUDED__
#define __ZMQ_PLAIN_MECHANISM_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;
    class session_base_t;

    class plain_mechanism_t : public mechanism_t
    {
    public:

        plain_mechanism_t (session_base_t *session_,
                           const std::string &peer_address_,
                           const options_t &options_);
        virtual ~plain_mechanism_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual int zap_msg_available ();
        virtual bool is_handshake_complete () const;

    private:

        enum state_t {
            sending_hello,
            waiting_for_hello,
            sending_welcome,
            waiting_for_welcome,
            sending_initiate,
            waiting_for_initiate,
            sending_ready,
            waiting_for_ready,
            waiting_for_zap_reply,
            ready
        };

        session_base_t * const session;

        const std::string peer_address;

        //  True iff we are awaiting reply from ZAP reply.
        bool expecting_zap_reply;

        state_t state;

        int produce_hello (msg_t *msg_) const;
        int produce_welcome (msg_t *msg_) const;
        int produce_initiate (msg_t *msg_) const;
        int produce_ready (msg_t *msg_) const;

        int process_hello (msg_t *msg_);
        int process_welcome (msg_t *msg);
        int process_ready (msg_t *msg_);
        int process_initiate (msg_t *msg_);

        void send_zap_request (const std::string &username,
                               const std::string &password);
        int receive_and_process_zap_reply ();
    };

}

#endif
