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

#ifndef __ZMQ_NULL_MECHANISM_HPP_INCLUDED__
#define __ZMQ_NULL_MECHANISM_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;
    class session_base_t;

    class null_mechanism_t : public mechanism_t
    {
    public:

        null_mechanism_t (session_base_t *session_,
                          const std::string &peer_address,
                          const options_t &options_);
        virtual ~null_mechanism_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual int zap_msg_available ();
        virtual status_t status () const;

    private:

        session_base_t * const session;

        char status_code [3];

        const std::string peer_address;

        bool ready_command_sent;
        bool error_command_sent;
        bool ready_command_received;
        bool error_command_received;
        bool zap_connected;
        bool zap_request_sent;
        bool zap_reply_received;

        int process_ready_command (
            const unsigned char *cmd_data, size_t data_size);
        int process_error_command (
            const unsigned char *cmd_data, size_t data_size);

        void send_zap_request ();
        int receive_and_process_zap_reply ();
    };

}

#endif
