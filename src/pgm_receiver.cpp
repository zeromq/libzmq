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

#include "precompiled.hpp"
#include "macros.hpp"

#if defined ZMQ_HAVE_OPENPGM

#include <new>

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
    LIBZMQ_UNUSED (io_thread_);
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
    for (peers_t::iterator it = peers.begin (), end = peers.end (); it != end;
         ++it) {
        if (it->second.decoder != NULL) {
            LIBZMQ_DELETE (it->second.decoder);
        }
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

bool zmq::pgm_receiver_t::restart_input ()
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
                return true;
            }
            //  Data error. Delete message decoder, mark the
            //  peer as not joined and drop remaining data.
            it->second.joined = false;
            LIBZMQ_DELETE (it->second.decoder);
            insize = 0;
        }
    }

    //  Resume polling.
    set_pollin (pipe_handle);
    set_pollin (socket_handle);

    active_tsi = NULL;
    in_event ();

    return true;
}

const zmq::endpoint_uri_pair_t &zmq::pgm_receiver_t::get_endpoint () const
{
    return _empty_endpoint;
}

void zmq::pgm_receiver_t::in_event ()
{
    // If active_tsi is not null, there is a pending restart_input.
    // Keep the internal state as is so that restart_input would process the right data
    if (active_tsi) {
        return;
    }

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
        insize = 0;
        void *tmp = NULL;
        ssize_t received = pgm_socket.receive (&tmp, &tsi);

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
                    LIBZMQ_DELETE (it->second.decoder);
                }
            }
            break;
        }

        //  New peer. Add it to the list of know but unjoint peers.
        if (it == peers.end ()) {
            peer_info_t peer_info = {false, NULL};
            it = peers.ZMQ_MAP_INSERT_OR_EMPLACE (*tsi, peer_info).first;
        }

        insize = static_cast<size_t> (received);
        inpos = (unsigned char *) tmp;

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

            //  We have to move data to the beginning of the first message.
            inpos += offset;
            insize -= offset;

            //  Mark the stream as joined.
            it->second.joined = true;

            //  Create and connect decoder for the peer.
            it->second.decoder =
              new (std::nothrow) v1_decoder_t (0, options.maxmsgsize);
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
            LIBZMQ_DELETE (it->second.decoder);
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
    while (session->pull_msg (&msg) == 0)
        msg.close ();
}

#endif
