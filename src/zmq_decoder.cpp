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

#include <stdlib.h>
#include <string.h>

#include "zmq_decoder.hpp"
#include "i_inout.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::zmq_decoder_t::zmq_decoder_t (size_t bufsize_) :
    decoder_t <zmq_decoder_t> (bufsize_),
    destination (NULL),
    prefix (NULL),
    prefix_size (0)
{
    zmq_msg_init (&in_progress);

    //  At the beginning, read one byte and go to one_byte_size_ready state.
    next_step (tmpbuf, 1, &zmq_decoder_t::one_byte_size_ready);
}

zmq::zmq_decoder_t::~zmq_decoder_t ()
{
    if (prefix)
        free (prefix);

    zmq_msg_close (&in_progress);
}

void zmq::zmq_decoder_t::set_inout (i_inout *destination_)
{
    destination = destination_;
}

void zmq::zmq_decoder_t::add_prefix (unsigned char *prefix_,
    size_t prefix_size_)
{
    prefix = malloc (prefix_size_);
    zmq_assert (prefix);
    memcpy (prefix, prefix_, prefix_size_);
    prefix_size = prefix_size_;
}

bool zmq::zmq_decoder_t::one_byte_size_ready ()
{
    //  First byte of size is read. If it is 0xff read 8-byte size.
    //  Otherwise allocate the buffer for message data and read the
    //  message data into it.
    if (*tmpbuf == 0xff)
        next_step (tmpbuf, 8, &zmq_decoder_t::eight_byte_size_ready);
    else {

        //  TODO:  Handle over-sized message decently.
        //  in_progress is initialised at this point so in theory we should
        //  close it before calling zmq_msg_init_size, however, it's a 0-byte
        //  message and thus we can treat it as uninitialised...
        int rc = zmq_msg_init_size (&in_progress, prefix_size + *tmpbuf);
        errno_assert (rc == 0);

        //  Fill in the message prefix if any.
        if (prefix)
            memcpy (zmq_msg_data (&in_progress), prefix, prefix_size);

        next_step ((unsigned char*) zmq_msg_data (&in_progress) + prefix_size,
            *tmpbuf, &zmq_decoder_t::message_ready);
    }
    return true;
}

bool zmq::zmq_decoder_t::eight_byte_size_ready ()
{
    //  8-byte size is read. Allocate the buffer for message body and
    //  read the message data into it.
    size_t size = (size_t) get_uint64 (tmpbuf);

    //  TODO:  Handle over-sized message decently.
    //  in_progress is initialised at this point so in theory we should
    //  close it before calling zmq_msg_init_size, however, it's a 0-byte
    //  message and thus we can treat it as uninitialised...
    int rc = zmq_msg_init_size (&in_progress, prefix_size + size);
    errno_assert (rc == 0);

    //  Fill in the message prefix if any.
    if (prefix)
        memcpy (zmq_msg_data (&in_progress), prefix, prefix_size);

    next_step ((unsigned char*) zmq_msg_data (&in_progress) + prefix_size ,
        size, &zmq_decoder_t::message_ready);
    return true;
}

bool zmq::zmq_decoder_t::message_ready ()
{
    //  Message is completely read. Push it further and start reading
    //  new message. (in_progress is a 0-byte message after this point.)
    if (!destination || !destination->write (&in_progress))
        return false;

    next_step (tmpbuf, 1, &zmq_decoder_t::one_byte_size_ready);
    return true;
}
