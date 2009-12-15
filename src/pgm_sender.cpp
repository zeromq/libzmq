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

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <iostream>

#include "io_thread.hpp"
#include "pgm_sender.hpp"
#include "err.hpp"
#include "wire.hpp"

zmq::pgm_sender_t::pgm_sender_t (io_thread_t *parent_, 
      const options_t &options_, const char *session_name_) :
    io_object_t (parent_),
    encoder (0, false),
    pgm_socket (false, options_),
    options (options_),
    session_name (session_name_),
    inout (NULL),
    out_buffer (NULL),
    out_buffer_size (0),
    write_size (0),
    write_pos (0), 
    first_message_offset (-1)
{
}

int zmq::pgm_sender_t::init (bool udp_encapsulation_, const char *network_)
{
    return pgm_socket.init (udp_encapsulation_, network_);
}

void zmq::pgm_sender_t::plug (i_inout *inout_)
{
    //  Alocate 2 fds for PGM socket.
    int downlink_socket_fd = 0;
    int uplink_socket_fd = 0;
    int rdata_notify_fd = 0;

    encoder.set_inout (inout_);

    //  Fill fds from PGM transport.
    pgm_socket.get_sender_fds 
        (&downlink_socket_fd, &uplink_socket_fd, &rdata_notify_fd);

    //  Add downlink_socket_fd into poller.
    handle = add_fd (downlink_socket_fd);

    //  Add uplink_socket_fd into the poller.
    uplink_handle = add_fd (uplink_socket_fd);

    //  Add rdata_notify_fd into the poller.
    rdata_notify_handle = add_fd (rdata_notify_fd);   

    //  Set POLLIN. We wont never want to stop polling for uplink = we never
    //  want to stop porocess NAKs.
    set_pollin (uplink_handle);
    set_pollin (rdata_notify_handle);

    //  Set POLLOUT for downlink_socket_handle.
    set_pollout (handle);

    inout = inout_;
}

void zmq::pgm_sender_t::unplug ()
{
    rm_fd (handle);
    rm_fd (uplink_handle);
    rm_fd (rdata_notify_handle);
    encoder.set_inout (NULL);
    inout = NULL;
}

void zmq::pgm_sender_t::revive ()
{
    set_pollout (handle);
    out_event ();
}

zmq::pgm_sender_t::~pgm_sender_t ()
{
    if (out_buffer) {
        pgm_socket.free_buffer (out_buffer);
        out_buffer = NULL;
    }
}

//  In event on sender side means NAK or SPMR receiving from some peer.
void zmq::pgm_sender_t::in_event ()
{
    pgm_socket.process_upstream ();
}

void zmq::pgm_sender_t::out_event ()
{
    //  POLLOUT event from send socket. If write buffer is empty, 
    //  try to read new data from the encoder.
    if (write_pos == write_size) {

        //  Get buffer if we do not have already one.
        if (!out_buffer) {
            out_buffer = (unsigned char*) 
                pgm_socket.get_buffer (&out_buffer_size);
        }

        assert (out_buffer_size > 0);

        //  First two bytes /sizeof (uint16_t)/ are used to store message 
        //  offset in following steps.
        unsigned char *bf = out_buffer + sizeof (uint16_t);
        write_size = out_buffer_size - sizeof (uint16_t);
        encoder.get_data (&bf, &write_size, &first_message_offset);
        write_pos = 0;

        //  If there are no data to write stop polling for output.
        if (!write_size) {
            reset_pollout (handle);
        } else {
            // Addning uint16_t for offset in a case when encoder returned > 0B.
            write_size += sizeof (uint16_t);
        }
    }

    //  If there are any data to write, write them into the socket.
    //  Note that all data has to written in one write_one_pkt_with_offset call.
    if (write_pos < write_size) {
        size_t nbytes = write_one_pkt_with_offset (out_buffer + write_pos, 
            write_size - write_pos, (uint16_t) first_message_offset);

        //  We can write either all data or 0 which means rate limit reached.
        zmq_assert (write_size - write_pos == nbytes || nbytes == 0);

        write_pos += nbytes;
    }
}

size_t zmq::pgm_sender_t::write_one_pkt_with_offset (unsigned char *data_, 
    size_t size_, uint16_t offset_)
{
    //  Put offset information in the buffer.
    put_uint16 (data_, offset_);
   
    //  Send data.
    size_t nbytes = pgm_socket.send (data_, size_);

    return nbytes;
}
#endif

