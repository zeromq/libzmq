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

#ifndef __ZMQ_CURVE_CLIENT_HPP_INCLUDED__
#define __ZMQ_CURVE_CLIENT_HPP_INCLUDED__

#include "platform.hpp"

#ifdef HAVE_LIBSODIUM
#include <sodium.h>

#if crypto_box_NONCEBYTES != 24 \
||  crypto_box_PUBLICKEYBYTES != 32 \
||  crypto_box_SECRETKEYBYTES != 32 \
||  crypto_box_ZEROBYTES != 32 \
||  crypto_box_BOXZEROBYTES != 16
#error "libsodium not built properly"
#endif

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;
    class session_base_t;

    class curve_client_t : public mechanism_t
    {
    public:

        curve_client_t (const options_t &options_);
        virtual ~curve_client_t ();

        // mechanism implementation
        virtual int next_handshake_command (msg_t *msg_);
        virtual int process_handshake_command (msg_t *msg_);
        virtual int encode (msg_t *msg_);
        virtual int decode (msg_t *msg_);
        virtual bool is_handshake_complete () const;

    private:

        enum state_t {
            send_hello,
            expect_welcome,
            send_initiate,
            expect_ready,
            connected
        };

        //  Current FSM state
        state_t state;

        //  Our public key (C)
        uint8_t public_key [crypto_box_PUBLICKEYBYTES];

        //  Our secret key (c)
        uint8_t secret_key [crypto_box_SECRETKEYBYTES];

        //  Our short-term public key (C')
        uint8_t cn_public [crypto_box_PUBLICKEYBYTES];

        //  Our short-term secret key (c')
        uint8_t cn_secret [crypto_box_SECRETKEYBYTES];

        //  Server's public key (S)
        uint8_t server_key [crypto_box_PUBLICKEYBYTES];

        //  Server's short-term public key (S')
        uint8_t cn_server [crypto_box_PUBLICKEYBYTES];

        //  Cookie received from server
        uint8_t cn_cookie [16 + 80];

        //  Intermediary buffer used to seepd up boxing and unboxing.
        uint8_t cn_precom [crypto_box_BEFORENMBYTES];

        //  Nonce
        uint64_t cn_nonce;

        int produce_hello (msg_t *msg_);
        int process_welcome (msg_t *msg_);
        int produce_initiate (msg_t *msg_);
        int process_ready (msg_t *msg_);
    };

}

#endif

#endif
