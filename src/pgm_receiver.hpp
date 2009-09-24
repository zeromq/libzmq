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

#ifndef __ZMQ_PGM_RECEIVER_HPP_INCLUDED__
#define __ZMQ_PGM_RECEIVER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM1

#include "io_object.hpp"
#include "i_engine.hpp"
#include "options.hpp"
#include "zmq_decoder.hpp"
#include "pgm_socket.hpp"

#include <map>

namespace zmq
{

    class pgm_receiver_t : public io_object_t, public i_engine
    {
    
    public:

        //  Creates gm_engine. Underlying PGM connection is initialised
        //  using network_ parameter.
        pgm_receiver_t (class io_thread_t *parent_, const options_t &options_,
            const char *session_name_);
        ~pgm_receiver_t ();

        int init (bool udp_encapsulation_, const char *network_);

        //  i_engine interface implementation.
        void plug (struct i_inout *inout_);
        void unplug ();
        void revive ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Map to hold TSI, joined and decoder for each peer.
        struct peer_info_t {
            bool joined;
            zmq_decoder_t *decoder;
        };

        struct tsi_comp {
            bool operator () (const pgm_tsi_t &ltsi, const pgm_tsi_t &rtsi) const
            {
                if (ltsi.sport < rtsi.sport)
                    return true;

                return (std::lexicographical_compare (ltsi.gsi.identifier, 
                    ltsi.gsi.identifier + 6, 
                    rtsi.gsi.identifier, rtsi.gsi.identifier + 6));
            }
        };

        typedef std::map <pgm_tsi_t, peer_info_t, tsi_comp> peer_t;
        peer_t peers;

        //  PGM socket.
        pgm_socket_t pgm_socket;

        //  Socket options.
        options_t options;

        //  Name of the session associated with the connecter.
        std::string session_name;

        //  Parent session.
        i_inout *inout;

        //  Poll handle associated with PGM socket.
        handle_t socket_handle;

        //  Poll handle associated with engine PGM waiting pipe.
        handle_t pipe_handle;

        pgm_receiver_t (const pgm_receiver_t&);
        void operator = (const pgm_receiver_t&);
    };

}

#endif

#endif
