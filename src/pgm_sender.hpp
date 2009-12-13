/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_PGM_SENDER_HPP_INCLUDED__
#define __ZMQ_PGM_SENDER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "stdint.hpp"
#include "io_object.hpp"
#include "i_engine.hpp"
#include "options.hpp"
#include "pgm_socket.hpp"
#include "zmq_encoder.hpp"

namespace zmq
{

    class pgm_sender_t : public io_object_t, public i_engine
    {

    public:
        pgm_sender_t (class io_thread_t *parent_, const options_t &options_, 
            const char *session_name_);
        ~pgm_sender_t ();

        int init (bool udp_encapsulation_, const char *network_);

        //  i_engine interface implementation.
        void plug (struct i_inout *inout_);
        void unplug ();
        void revive ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Send one APDU with first message offset information. 
        //  Note that first 2 bytes in data_ are used to store the offset_
        //  and thus user data has to start at data_ + sizeof (uint16_t).
        size_t write_one_pkt_with_offset (unsigned char *data_, size_t size_,
            uint16_t offset_);

        //  Message encoder.
        zmq_encoder_t encoder;

        //  PGM socket.
        pgm_socket_t pgm_socket;

        //  Socket options.
        options_t options;

        //  Name of the session associated with the connecter.
        std::string session_name;

        //  Poll handle associated with PGM socket.
        handle_t handle;
        handle_t uplink_handle;
        handle_t rdata_notify_handle;

        //  Parent session.
        i_inout *inout;

        //  Output buffer from pgm_socket.
        unsigned char *out_buffer;
        
        //  Output buffer size.
        size_t out_buffer_size;

        size_t write_size;
        size_t write_pos;

        //  Offset of the first mesage in data chunk taken from encoder.
        int first_message_offset;

        pgm_sender_t (const pgm_sender_t&);
        void operator = (const pgm_sender_t&);
    };

}
#endif

#endif
