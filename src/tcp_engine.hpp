/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_TCP_ENGINE_HPP_INCLUDED__
#define __ZMQ_TCP_ENGINE_HPP_INCLUDED__

#include <stddef.h>

#include "fd.hpp"
#include "i_engine.hpp"
#include "io_object.hpp"
#include "encoder.hpp"
#include "decoder.hpp"
#include "options.hpp"

namespace zmq
{

    class tcp_engine_t : public io_object_t, public i_engine
    {
    public:

        tcp_engine_t (fd_t fd_, const options_t &options_);
        ~tcp_engine_t ();

        //  i_engine interface implementation.
        void plug (class io_thread_t *io_thread_, class session_t *session_);
        void unplug ();
        void terminate ();
        void activate_in ();
        void activate_out ();

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

    private:

        //  Function to handle network disconnections.
        void error ();

        //  Associates a socket with a native socket descriptor.
        int open (fd_t fd_, int sndbuf_, int rcvbuf_);
         
        //  Closes the underlying socket.
        int close ();

        //  Writes data to the socket. Returns the number of bytes actually
        //  written (even zero is to be considered to be a success). In case
        //  of error or orderly shutdown by the other peer -1 is returned.
        int write (const void *data_, size_t size_);

        //  Reads data from the socket (up to 'size' bytes). Returns the number
        //  of bytes actually read (even zero is to be considered to be
        //  a success). In case of error or orderly shutdown by the other
        //  peer -1 is returned.
        int read (void *data_, size_t size_);

        //  Underlying socket.
        fd_t s;

        handle_t handle;

        unsigned char *inpos;
        size_t insize;
        decoder_t decoder;

        unsigned char *outpos;
        size_t outsize;
        encoder_t encoder;

        //  The session this engine is attached to.
        class session_t *session;

        //  Detached transient session.
        class session_t *leftover_session;

        options_t options;

        bool plugged;

        tcp_engine_t (const tcp_engine_t&);
        const tcp_engine_t &operator = (const tcp_engine_t&);
    };

}

#endif
