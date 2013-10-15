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

#include "platform.hpp"

#if defined ZMQ_HAVE_OPENPGM

#include <new>

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "pgm_receiver.hpp"
#include "session_base.hpp"
#include "v1_decoder.hpp"
#include "stdint.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::pgm_receiver_t::pgm_receiver_t (class io_thread_t *parent_, 
      const options_t &options_) :
    io_object_t (parent_),
    has_rx_timer (false),
    pgm_socket (true, options_),
    options (options_),
    session (NULL),
    active_tsi (NULL),
    insize (0)
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

void zmq::pgm_receiver_t::plug (io_thread_t *io_thread_,
    session_base_t *session_)
{
    //  Retrieve PGM fds and start polling.
    fd_t socket_fd = retired_fd;
    fd_t waiting_pipe_fd = retired_fd;
    pgm_socket.get_receiver_fds (&socket_fd, &waiting_pipe_fd);
    socket_handle = add_fd (socket_fd);
    pipe_handle = add_fd (waiting_pipe_fd);
    set_pollin (pipe_handle);
    set_pollin (socket_handle);

    session = session_;

    //  If there are any subscriptions already queued in the session, drop them.
    drop_subscriptions ();
}

void zmq::pgm_receiver_t::unplug ()
{
    //  Delete decoders.
    for (peers_t::iterator it = peers.begin (); it != peers.end (); ++it) {
        if (it->second.decoder != NULL)
            delete it->second.decoder;
    }
    peers.clear ();
    active_tsi = NULL;

    if (has_rx_timer) {
        cancel_timer (rx_timer_id);
        has_rx_timer = false;
    }

    rm_fd (socket_handle);
    rm_fd (pipe_handle);

    session = NULL;
}

void zmq::pgm_receiver_t::terminate ()
{
    unplug ();
    delete this;
}

void zmq::pgm_receiver_t::restart_output ()
{
    drop_subscriptions ();
}

void zmq::pgm_receiver_t::restart_input ()
{
    zmq_assert (session != NULL);
    zmq_assert (active_tsi != NULL);

    const peers_t::iterator it = peers.find (*active_tsi);
    zmq_assert (it != peers.end ());
    zmq_assert (it->second.joined);

    //  Push the pending message into the session.
    int rc = session->push_msg (it->second.decoder->msg ());
    errno_assert (rc == 0);

    if (insize > 0) {
        rc = process_input (it->second.decoder);
        if (rc == -1) {
            //  HWM reached; we will try later.
            if (errno == EAGAIN) {
                session->flush ();
                return;
            }
            //  Data error. Delete message decoder, mark the
            //  peer as not joined and drop remaining data.
            it->second.joined = false;
            delete it->second.decoder;
            it->second.decoder = NULL;
            insize = 0;
        }
    }

    //  Resume polling.
    set_pollin (pipe_handle);
    set_pollin (socket_handle);

    active_tsi = NULL;
    in_event ();
}

void zmq::pgm_receiver_t::in_event ()
{
    // Read data from the underlying pgm_socket.
    const pgm_tsi_t *tsi = NULL;

    if (has_rx_timer) {
        cancel_timer (rx_timer_id);
        has_rx_timer = false;
    }

    //  TODO: This loop can effectively block other engines in the same I/O
    //  thread in the case of high load.
    while (true) {

        //  Get new batch of data.
        //  Note the workaround made not to break strict-aliasing rules.
        void *tmp = NULL;
        ssize_t received = pgm_socket.receive (&tmp, &tsi);
        inpos = (unsigned char*) tmp;

        //  No data to process. This may happen if the packet received is
        //  neither ODATA nor ODATA.
        if (received == 0) {
            if (errno == ENOMEM || errno == EBUSY) {
                const long timeout = pgm_socket.get_rx_timeout ();
                add_timer (timeout, rx_timer_id);
                has_rx_timer = true;
            }
            break;
        }

        //  Find the peer based on its TSI.
        peers_t::iterator it = peers.find (*tsi);

        //  Data loss. Delete decoder and mark the peer as disjoint.
        if (received == -1) {
            if (it != peers.end ()) {
                it->second.joined = false;
                if (it->second.decoder != NULL) {
                    delete it->second.decoder;
                    it->second.decoder = NULL;
                }
            }
            break;
        }

        //  New peer. Add it to the list of know but unjoint peers.
        if (it == peers.end ()) {
            peer_info_t peer_info = {false, NULL};
            it = peers.insert (peers_t::value_type (*tsi, peer_info)).first;
        }

        insize = static_cast <size_t> (received);

        //  Read the offset of the fist message in the current packet.
        zmq_assert (insize >= sizeof (uint16_t));
        uint16_t offset = get_uint16 (inpos);
        inpos += sizeof (uint16_t);
        insize -= sizeof (uint16_t);

        //  Join the stream if needed.
        if (!it->second.joined) {

            //  There is no beginning of the message in current packet.
            //  Ignore the data.
            if (offset == 0xffff)
                continue;

            zmq_assert (offset <= insize);
            zmq_assert (it->second.decoder == NULL);

            //  We have to move data to the begining of the first message.
            inpos += offset;
            insize -= offset;

            //  Mark the stream as joined.
            it->second.joined = true;

            //  Create and connect decoder for the peer.
            it->second.decoder = new (std::nothrow)
                v1_decoder_t (0, options.maxmsgsize);
            alloc_assert (it->second.decoder);
        }

        int rc = process_input (it->second.decoder);
        if (rc == -1) {
            if (errno == EAGAIN) {
                active_tsi = tsi;

                //  Stop polling.
                reset_pollin (pipe_handle);
                reset_pollin (socket_handle);

                break;
            }

            it->second.joined = false;
            delete it->second.decoder;
            it->second.decoder = NULL;
            insize = 0;
        }
    }

    //  Flush any messages decoder may have produced.
    session->flush ();
}

int zmq::pgm_receiver_t::process_input (v1_decoder_t *decoder)
{
    zmq_assert (session != NULL);

    while (insize > 0) {
        size_t n = 0;
        int rc = decoder->decode (inpos, insize, n);
        if (rc == -1)
            return -1;
        inpos += n;
        insize -= n;
        if (rc == 0)
            break;
        rc = session->push_msg (decoder->msg ());
        if (rc == -1) {
            errno_assert (errno == EAGAIN);
            return -1;
        }
    }
    return 0;
}


void zmq::pgm_receiver_t::timer_event (int token)
{
    zmq_assert (token == rx_timer_id);

    //  Timer cancels on return by poller_base.
    has_rx_timer = false;
    in_event ();
}

void zmq::pgm_receiver_t::drop_subscriptions ()
{
    msg_t msg;
    msg.init ();
    while (session->pull_msg (&msg))
        msg.close ();
}

#endif

