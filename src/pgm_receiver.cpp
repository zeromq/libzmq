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

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM

#include <new>

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "pgm_receiver.hpp"
#include "err.hpp"
#include "stdint.hpp"
#include "wire.hpp"
#include "i_inout.hpp"

zmq::pgm_receiver_t::pgm_receiver_t (class io_thread_t *parent_, 
      const options_t &options_) :
    io_object_t (parent_),
    pgm_socket (true, options_),
    options (options_),
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
    //  Retrieve PGM fds and start polling.
    int socket_fd;
    int waiting_pipe_fd;
    pgm_socket.get_receiver_fds (&socket_fd, &waiting_pipe_fd);
    socket_handle = add_fd (socket_fd);
    pipe_handle = add_fd (waiting_pipe_fd);
    set_pollin (pipe_handle);
    set_pollin (socket_handle);

    inout = inout_;
}

void zmq::pgm_receiver_t::unplug ()
{
    //  Delete decoders.
    for (peers_t::iterator it = peers.begin (); it != peers.end (); it++) {
        if (it->second.decoder != NULL)
            delete it->second.decoder;
    }
    peers.clear ();

    //  Stop polling.
    rm_fd (socket_handle);
    rm_fd (pipe_handle);

    inout = NULL;
}

void zmq::pgm_receiver_t::revive ()
{
    zmq_assert (false);
}

void zmq::pgm_receiver_t::in_event ()
{
    // Read data from the underlying pgm_socket.
    unsigned char *data = NULL;
    const pgm_tsi_t *tsi = NULL;

    //  TODO: This loop can effectively block other engines in the same I/O
    //  thread in the case of high load.
    while (true) {

        //  Get new batch of data.
        ssize_t received = pgm_socket.receive ((void**) &data, &tsi);

        //  No data to process. This may happen if the packet received is
        //  neither ODATA nor ODATA.
        if (received == 0)
            break;

        //  Find the peer based on its TSI.
        peers_t::iterator it = peers.find (*tsi);

        //  Data loss. Delete decoder and mark the peer as disjoint.
        if (received == -1) {
            zmq_assert (it != peers.end ());
            it->second.joined = false;
            if (it->second.decoder != NULL) {
                delete it->second.decoder;
                it->second.decoder = NULL;
            }
            break;
        }

        //  New peer. Add it to the list of know but unjoint peers.
        if (it == peers.end ()) {
            peer_info_t peer_info = {false, NULL};
            it = peers.insert (std::make_pair (*tsi, peer_info)).first;
        }

        //  Read the offset of the fist message in the current packet.
        zmq_assert ((size_t) received >= sizeof (uint16_t));
        uint16_t offset = get_uint16 (data);
        data += sizeof (uint16_t);
        received -= sizeof (uint16_t);

        //  Join the stream if needed.
        if (!it->second.joined) {

            //  There is no beginning of the message in current packet.
            //  Ignore the data.
            if (offset == 0xffff)
                continue;

            zmq_assert (offset <= received);
            zmq_assert (it->second.decoder == NULL);

            //  We have to move data to the begining of the first message.
            data += offset;
            received -= offset;

            //  Mark the stream as joined.
            it->second.joined = true;

            //  Create and connect decoder for the peer.
            it->second.decoder = new (std::nothrow) zmq_decoder_t (0, NULL, 0);
            it->second.decoder->set_inout (inout);
        }

        //  Push all the data to the decoder.
        //  TODO: process_buffer may not process entire buffer!
        ssize_t processed = it->second.decoder->process_buffer (data, received);
        zmq_assert (processed == received);
    }

    //  Flush any messages decoder may have produced.
    inout->flush ();
}

#endif

