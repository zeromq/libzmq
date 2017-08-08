/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_PGM_RECEIVER_HPP_INCLUDED__
#define __ZMQ_PGM_RECEIVER_HPP_INCLUDED__

#if defined ZMQ_HAVE_OPENPGM

#include <map>
#include <algorithm>

#include "io_object.hpp"
#include "i_engine.hpp"
#include "options.hpp"
#include "v1_decoder.hpp"
#include "pgm_socket.hpp"

namespace zmq
{

    class io_thread_t;
    class session_base_t;

    class pgm_receiver_t : public io_object_t, public i_engine
    {

    public:

        pgm_receiver_t (zmq::io_thread_t *parent_, const options_t &options_);
        ~pgm_receiver_t ();

        int init (bool udp_encapsulation_, const char *network_);

        //  i_engine interface implementation.
        void plug (zmq::io_thread_t *io_thread_,
            zmq::session_base_t *session_);
        void terminate ();
        void restart_input ();
        void restart_output ();
        void zap_msg_available () {}
        const char *get_endpoint () const;

        //  i_poll_events interface implementation.
        void in_event ();
        void timer_event (int token);

    private:

        //  Unplug the engine from the session.
        void unplug ();

        //  Decode received data (inpos, insize) and forward decoded
        //  messages to the session.
        int process_input (v1_decoder_t *decoder);

        //  PGM is not able to move subscriptions upstream. Thus, drop all
        //  the pending subscriptions.
        void drop_subscriptions ();

        //  RX timeout timer ID.
        enum {rx_timer_id = 0xa1};

        //  RX timer is running.
        bool has_rx_timer;

        //  If joined is true we are already getting messages from the peer.
        //  It it's false, we are getting data but still we haven't seen
        //  beginning of a message.
        struct peer_info_t
        {
            bool joined;
            v1_decoder_t *decoder;
        };

        struct tsi_comp
        {
            bool operator () (const pgm_tsi_t &ltsi,
                const pgm_tsi_t &rtsi) const
            {
                uint32_t ll[2], rl[2];
                memcpy (ll, &ltsi, sizeof (ll));
                memcpy (rl, &rtsi, sizeof (rl));
                return (ll[0] < rl[0]) || (ll[0] == rl[0] && ll[1] < rl[1]);
            }
        };

        typedef std::map <pgm_tsi_t, peer_info_t, tsi_comp> peers_t;
        peers_t peers;

        //  PGM socket.
        pgm_socket_t pgm_socket;

        //  Socket options.
        options_t options;

        //  Associated session.
        zmq::session_base_t *session;

        const pgm_tsi_t *active_tsi;

        //  Number of bytes not consumed by the decoder due to pipe overflow.
        size_t insize;

        //  Pointer to data still waiting to be processed by the decoder.
        const unsigned char *inpos;

        //  Poll handle associated with PGM socket.
        handle_t socket_handle;

        //  Poll handle associated with engine PGM waiting pipe.
        handle_t pipe_handle;

        pgm_receiver_t (const pgm_receiver_t&);
        const pgm_receiver_t &operator = (const pgm_receiver_t&);
    };

}

#endif

#endif
