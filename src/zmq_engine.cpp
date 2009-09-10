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

#include "zmq_engine.hpp"
#include "io_thread.hpp"
#include "i_inout.hpp"
#include "config.hpp"
#include "err.hpp"

zmq::zmq_engine_t::zmq_engine_t (io_thread_t *parent_, fd_t fd_) :
    io_object_t (parent_),
    insize (0),
    inpos (0),
    outsize (0),
    outpos (0),
    inout (NULL)
{
    //  Allocate read & write buffer.
    inbuf = (unsigned char*) malloc (in_batch_size);
    zmq_assert (inbuf);
    outbuf = (unsigned char*) malloc (out_batch_size);
    zmq_assert (outbuf);

    //  Initialise the underlying socket.
    int rc = tcp_socket.open (fd_);
    zmq_assert (rc == 0);
}

zmq::zmq_engine_t::~zmq_engine_t ()
{
    free (outbuf);
    free (inbuf);
}

void zmq::zmq_engine_t::plug (i_inout *inout_)
{
    encoder.set_inout (inout_);
    decoder.set_inout (inout_);

    handle = add_fd (tcp_socket.get_fd ());
    set_pollin (handle);
    set_pollout (handle);

    inout = inout_;

    //  Flush all the data that may have been already received downstream.
    in_event ();
}

void zmq::zmq_engine_t::unplug ()
{
    rm_fd (handle);
    encoder.set_inout (NULL);
    decoder.set_inout (NULL);
    inout = NULL;
}

void zmq::zmq_engine_t::in_event ()
{
    //  If there's no data to process in the buffer, read new data.
    if (inpos == insize) {

        //  Read as much data as possible to the read buffer.
        insize = tcp_socket.read (inbuf, in_batch_size);
        inpos = 0;

        //  Check whether the peer has closed the connection.
        if (insize == -1) {
            insize = 0;
            error ();
            return;
        }
    }

    //  Following code should be executed even if there's not a single byte in
    //  the buffer. There still can be a decoded messages stored in the decoder.

    //  Push the data to the decoder.
    int nbytes = decoder.write (inbuf + inpos, insize - inpos);

    //  Adjust read position. Stop polling for input if we got stuck.
    inpos += nbytes;
    if (inpos < insize)
        reset_pollin (handle);

    //  Flush all messages the decoder may have produced.
    inout->flush ();
}

void zmq::zmq_engine_t::out_event ()
{
    //  If write buffer is empty, try to read new data from the encoder.
    if (outpos == outsize) {

        outsize = encoder.read (outbuf, out_batch_size);
        outpos = 0;

        //  If there is no data to send, stop polling for output.
        if (outsize == 0)
            reset_pollout (handle);
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket.
    if (outpos < outsize) {
        int nbytes = tcp_socket.write (outbuf + outpos, outsize - outpos);

        //  Handle problems with the connection.
        if (nbytes == -1) {
            error ();
            return;
        }

        outpos += nbytes;
    }
}

void zmq::zmq_engine_t::revive ()
{
    set_pollout (handle);
}

void zmq::zmq_engine_t::error ()
{
    zmq_assert (inout);
    inout->detach ();
    unplug ();
    delete this;
}
