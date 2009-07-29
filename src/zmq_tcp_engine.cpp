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

#include "zmq_tcp_engine.hpp"
#include "config.hpp"
#include "i_session.hpp"
#include "err.hpp"

zs::zmq_tcp_engine_t::zmq_tcp_engine_t (fd_t fd_) :
    poller (NULL),
    session (NULL),
    terminating (false),
    insize (0),
    inpos (0),
    outsize (0),
    outpos (0)
{
    //  Allocate read & write buffer.
    inbuf = new unsigned char [in_batch_size];
    zs_assert (inbuf);
    outbuf = new unsigned char [out_batch_size];
    zs_assert (outbuf);

    //  Attach the socket.
    int rc = socket.open (fd_);
    zs_assert (rc == 0);
}

void zs::zmq_tcp_engine_t::attach (i_poller *poller_, i_session *session_)
{
    zs_assert (!poller);
    poller = poller_;
    zs_assert (!session);
    session = session_;
    encoder.set_session (session);
    decoder.set_session (session);

    //  Let session know we are here.
    session->set_engine (this);

    //  Register the engine with the polling thread.
    handle = poller->add_fd (socket.get_fd (), this);
    poller->set_pollin (handle);
    poller->set_pollout (handle);

    //  Flush any pending inbound messages.
    in_event ();
}

void zs::zmq_tcp_engine_t::detach ()
{
    zs_assert (poller);
    poller->rm_fd (handle);
    poller = NULL;
    zs_assert (session);
    session->set_engine (NULL);
    session = NULL;
    encoder.set_session (NULL);
    decoder.set_session (NULL);
}

void zs::zmq_tcp_engine_t::revive ()
{
    zs_assert (poller);
    poller->set_pollout (handle);
}

void zs::zmq_tcp_engine_t::schedule_terminate ()
{
    terminating = true;
}

void zs::zmq_tcp_engine_t::terminate ()
{
    delete this;
}

void zs::zmq_tcp_engine_t::shutdown ()
{
    delete this;
}

zs::zmq_tcp_engine_t::~zmq_tcp_engine_t ()
{
    detach ();
    delete [] outbuf;
    delete [] inbuf;
}

void zs::zmq_tcp_engine_t::in_event ()
{
    //  If there's no data to process in the buffer, read new data.
    if (inpos == insize) {

        //  Read as much data as possible to the read buffer.
        insize = socket.read (inbuf, in_batch_size);
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
        poller->reset_pollin (handle);

    //  If at least one byte was processed, flush all messages the decoder
    //  may have produced. If engine is disconnected from session, no need
    //  to flush the messages. It's important that flush is called at the
    //  very end of in_event as it may invoke in_event itself.
    if (nbytes > 0 && session)
        session->flush ();
}

void zs::zmq_tcp_engine_t::out_event ()
{
    //  If write buffer is empty, try to read new data from the encoder.
    if (outpos == outsize) {

        outsize = encoder.read (outbuf, out_batch_size);
        outpos = 0;

        //  If there are no more pipes, engine can be deallocated.
        if (terminating) {
            terminate ();
            return;
        }

        //  If there is no data to send, stop polling for output.
        if (outsize == 0)
            poller->reset_pollout (handle);
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket.
    if (outpos < outsize) {
        int nbytes = socket.write (outbuf + outpos, outsize - outpos);

        //  Handle problems with the connection.
        if (nbytes == -1) {
            error ();
            return;
        }

        outpos += nbytes;
    }
}

void zs::zmq_tcp_engine_t::timer_event ()
{
    zs_assert (false);
}

void zs::zmq_tcp_engine_t::error ()
{
    zs_assert (false);
}

