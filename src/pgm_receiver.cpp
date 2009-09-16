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
    decoder (NULL),
    pgm_socket (true, options_),
    options (options_),
    session_name (session_name_),
    joined (false),
    inout (NULL)
{
}

zmq::pgm_receiver_t::~pgm_receiver_t ()
{
    if (decoder)
        delete decoder;
}

int zmq::pgm_receiver_t::init (const char *network_)
{
    decoder = new zmq_decoder_t;
    zmq_assert (decoder);

    return pgm_socket.init (network_);
}

void zmq::pgm_receiver_t::plug (i_inout *inout_)
{
    //  Allocate 2 fds one for socket second for waiting pipe.
    int socket_fd;
    int waiting_pipe_fd;

    decoder->set_inout (inout_);

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
    rm_fd (socket_handle);
    rm_fd (pipe_handle);
    decoder->set_inout (NULL);
    inout = NULL;
}

void zmq::pgm_receiver_t::revive ()
{
    zmq_assert (false);
}

void zmq::pgm_receiver_t::reconnect ()
{
    //  Save inout ptr.
    i_inout *inout_tmp = inout;

    //  PGM receiver is not joined anymore.
    joined = false;    

    //  Unplug - plug PGM transport.
    unplug ();
    delete decoder;
    decoder = new zmq_decoder_t;
    zmq_assert (decoder);
    plug (inout_tmp);
}

//  POLLIN event from socket or waiting_pipe.
void zmq::pgm_receiver_t::in_event ()
{
    void *data_with_offset;
    ssize_t nbytes = 0;

    //  Read all data from pgm socket.
    while ((nbytes = receive_with_offset (&data_with_offset)) > 0) {
        
        //  Push all the data to the decoder.
        decoder->write ((unsigned char*)data_with_offset, nbytes);
    }

    //  Flush any messages decoder may have produced to the dispatcher.
    inout->flush ();

    //  Data loss detected.
    if (nbytes == -1) {

        //  Recreate PGM transport.
        reconnect ();
    }
}

void zmq::pgm_receiver_t::out_event ()
{
    zmq_assert (false);
}

ssize_t zmq::pgm_receiver_t::receive_with_offset 
    (void **data_)
{

    //  Data from PGM socket.
    void *rd = NULL;
    unsigned char *raw_data = NULL;

    // Read data from underlying pgm_socket.
    ssize_t nbytes = pgm_socket.receive ((void**) &rd);
    raw_data = (unsigned char*) rd;

    //  No ODATA or RDATA.
    if (!nbytes)
        return 0;

    //  Data loss.
    if (nbytes == -1) {
        return -1;
    }

    // Read offset of the fist message in current APDU.
    uint16_t apdu_offset = get_uint16 (raw_data);

    // Shift raw_data & decrease nbytes by the first message offset 
    // information (sizeof uint16_t).
    *data_ = raw_data +  sizeof (uint16_t);
    nbytes -= sizeof (uint16_t);

    //  There is not beginning of the message in current APDU and we
    //  are not joined jet -> throwing data.
    if (apdu_offset == 0xFFFF && !joined) {
        *data_ = NULL;
        return 0;
    }

    //  Now is the possibility to join the stream.
    if (!joined) {
           
        //  We have to move data to the begining of the first message.
        *data_ = (unsigned char *)*data_ + apdu_offset;
        nbytes -= apdu_offset;

        // Joined the stream.
        joined = true;

        zmq_log (2, "joined into the stream, %s(%i)\n", 
            __FILE__, __LINE__);
    }

    return nbytes;
}
#endif

