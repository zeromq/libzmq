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

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM

#include <iostream>

#include "pgm_receiver.hpp"
#include "err.hpp"
#include "stdint.hpp"
#include "wire.hpp"
#include "i_inout.hpp"

//#define PGM_RECEIVER_DEBUG
//#define PGM_RECEIVER_DEBUG_LEVEL 1

// level 1 = key behaviour
// level 2 = processing flow
// level 4 = infos

#ifndef PGM_RECEIVER_DEBUG
#   define zmq_log(n, ...)  while (0)
#else
#   define zmq_log(n, ...)    do { if ((n) <= PGM_RECEIVER_DEBUG_LEVEL) \
        { printf (__VA_ARGS__);}} while (0)
#endif

zmq::pgm_receiver_t::pgm_receiver_t (class io_thread_t *parent_, 
      const options_t &options_, const char *session_name_) :
    io_object_t (parent_),
    pgm_socket (true, options_),
    options (options_),
    session_name (session_name_),
    inout (NULL)
{
}

zmq::pgm_receiver_t::~pgm_receiver_t ()
{
    //  Destructor should not be called before unplug.
    zmq_assert (peers.empty ());
}

int zmq::pgm_receiver_t::init (bool udp_encapsulation_, const char *network_)
{
    return pgm_socket.init (udp_encapsulation_, network_);
}

void zmq::pgm_receiver_t::plug (i_inout *inout_)
{
    //  Allocate 2 fds one for socket second for waiting pipe.
    int socket_fd;
    int waiting_pipe_fd;

    //  Fill socket_fd and waiting_pipe_fd from PGM transport
    pgm_socket.get_receiver_fds (&socket_fd, &waiting_pipe_fd);

    //  Add socket_fd into poller.
    socket_handle = add_fd (socket_fd);

    //  Add waiting_pipe_fd into poller.
    pipe_handle = add_fd (waiting_pipe_fd);

    //  Set POLLIN for both handlers.
    set_pollin (pipe_handle);
    set_pollin (socket_handle);

    inout = inout_;
}

void zmq::pgm_receiver_t::unplug ()
{
    //  Delete decoders.
    for (peer_t::iterator it = peers.begin (); it != peers.end (); it++) {
        if (it->second.decoder != NULL)
            delete it->second.decoder;
    }

    peers.clear ();

    rm_fd (socket_handle);
    rm_fd (pipe_handle);
    inout = NULL;
}

void zmq::pgm_receiver_t::revive ()
{
    zmq_assert (false);
}

//  POLLIN event from socket or waiting_pipe.
void zmq::pgm_receiver_t::in_event ()
{
    //  Iterator to peers map.
    peer_t::iterator it;

    //  Data from PGM socket.
    unsigned char *raw_data = NULL;
    const pgm_tsi_t *tsi = NULL;
    ssize_t nbytes = 0;

    do {

        // Read data from underlying pgm_socket.
        nbytes = pgm_socket.receive ((void**) &raw_data, &tsi);

        //  No ODATA or RDATA.
        if (!nbytes)
            break;

        //  Fid TSI in peers list.
        it = peers.find (*tsi);

        //  Data loss.
        if (nbytes == -1) {

            zmq_assert (it != peers.end ());

            //  Delete decoder and set joined to false.
            it->second.joined = false;
            
            if (it->second.decoder != NULL) {
                delete it->second.decoder;
                it->second.decoder = NULL;
            }

            break;
        }

        // Read offset of the fist message in current APDU.
        zmq_assert ((size_t) nbytes >= sizeof (uint16_t));
        uint16_t apdu_offset = get_uint16 (raw_data);

        // Shift raw_data & decrease nbytes by the first message offset 
        // information (sizeof uint16_t).
        raw_data +=  sizeof (uint16_t);
        nbytes -= sizeof (uint16_t);

        //  New peer.
        if (it == peers.end ()) {

            peer_info_t peer_info = {false, NULL};
            it = peers.insert (std::make_pair (*tsi, peer_info)).first;

#ifdef ZMQ_HAVE_OPENPGM1
            zmq_log (1, "New peer TSI: %s, %s(%i).\n", pgm_print_tsi (tsi),
                __FILE__, __LINE__);
#elif ZMQ_HAVE_OPENPGM2
            zmq_log (1, "New peer TSI: %s, %s(%i).\n", pgm_tsi_print (tsi),
                __FILE__, __LINE__);
#endif
        }

        //  There is not beginning of the message in current APDU and we
        //  are not joined jet -> throwing data.
        if (apdu_offset == 0xFFFF && !it->second.joined) {
            break;
        }

        //  Now is the possibility to join the stream.
        if (!it->second.joined) {
 
            zmq_assert (apdu_offset <= nbytes);
            zmq_assert (it->second.decoder == NULL);

            //  We have to move data to the begining of the first message.
            raw_data += apdu_offset;
            nbytes -= apdu_offset;

            // Joined the stream.
            it->second.joined = true;

            //  Create and connect decoder for joined peer.
            it->second.decoder = new zmq_decoder_t;
            it->second.decoder->set_inout (inout);

#ifdef ZMQ_HAVE_OPENPGM1
            zmq_log (1, "Peer %s joined into the stream, %s(%i)\n", 
                pgm_print_tsi (tsi), __FILE__, __LINE__);
#elif ZMQ_HAVE_OPENPGM2
             zmq_log (1, "Peer %s joined into the stream, %s(%i)\n", 
                pgm_tsi_print (tsi), __FILE__, __LINE__);
#endif
        }

        if (nbytes > 0) {
        
            //  Push all the data to the decoder.
            it->second.decoder->write (raw_data, nbytes);
        }

    } while (nbytes > 0);
    
    //  Flush any messages decoder may have produced to the dispatcher.
    inout->flush ();

}

void zmq::pgm_receiver_t::out_event ()
{
    zmq_assert (false);
}

#endif

