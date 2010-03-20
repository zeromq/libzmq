/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#if defined ZMQ_HAVE_OPENPGM

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <map>
#include <algorithm>

#include "io_object.hpp"
#include "i_engine.hpp"
#include "options.hpp"
#include "zmq_decoder.hpp"
#include "pgm_socket.hpp"

namespace zmq
{

    class pgm_receiver_t : public io_object_t, public i_engine
    {
    
    public:

        pgm_receiver_t (class io_thread_t *parent_, const options_t &options_);
        ~pgm_receiver_t ();

        int init (bool udp_encapsulation_, const char *network_);

        //  i_engine interface implementation.
        void plug (struct i_inout *inout_);
        void unplug ();
        void revive ();
        void resume_input ();

        //  i_poll_events interface implementation.
        void in_event ();

    private:

        //  If joined is true we are already getting messages from the peer.
        //  It it's false, we are getting data but still we haven't seen
        //  beginning of a message.
        struct peer_info_t
        {
            bool joined;
            zmq_decoder_t *decoder;
        };

        struct tsi_comp
        {
            inline bool operator () (const pgm_tsi_t &ltsi,
                const pgm_tsi_t &rtsi) const
            {
                if (ltsi.sport < rtsi.sport)
                    return true;

                return (std::lexicographical_compare (ltsi.gsi.identifier, 
                    ltsi.gsi.identifier + 6, 
                    rtsi.gsi.identifier, rtsi.gsi.identifier + 6));
            }
        };

        typedef std::map <pgm_tsi_t, peer_info_t, tsi_comp> peers_t;
        peers_t peers;

        //  PGM socket.
        pgm_socket_t pgm_socket;

        //  Socket options.
        options_t options;

        //  Parent session.
        i_inout *inout;

        //  Most recently used decoder.
        zmq_decoder_t *mru_decoder;

        //  Number of bytes not consumed by the decoder due to pipe overflow.
        size_t pending_bytes;

        //  Pointer to data still waiting to be processed by the decoder.
        unsigned char *pending_ptr;

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
