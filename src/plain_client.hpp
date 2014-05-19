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

#ifndef __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__
#define __ZMQ_PLAIN_CLIENT_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;

    class plain_client_t : public mechanism_t
    {
    public:

        plain_client_t (const options_t &options_);
        virtual ~plain_client_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual status_t status () const;

    private:

        enum state_t {
            sending_hello,
            waiting_for_welcome,
            sending_initiate,
            waiting_for_ready,
            error_command_received,
            ready
        };

        state_t state;

        int produce_hello (msg_t *msg_) const;
        int produce_initiate (msg_t *msg_) const;

        int process_welcome (
            const unsigned char *cmd_data, size_t data_size);
        int process_ready (
            const unsigned char *cmd_data, size_t data_size);
        int process_error (
            const unsigned char *cmd_data, size_t data_size);
    };

}

#endif
