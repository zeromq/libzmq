/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include <stdlib.h>
#include <string.h>

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "raw_decoder.hpp"
#include "err.hpp"

zmq::raw_decoder_t::raw_decoder_t (size_t bufsize_) :
    bufsize (bufsize_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    buffer = (unsigned char *) malloc (bufsize);
    alloc_assert (buffer);
}

zmq::raw_decoder_t::~raw_decoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);

    free (buffer);
}

void zmq::raw_decoder_t::get_buffer (unsigned char **data_, size_t *size_)
{
    *data_ = buffer;
    *size_ = bufsize;
}

int zmq::raw_decoder_t::decode (const uint8_t *data_, size_t size_,
    size_t &bytes_used_)
{
    int rc = in_progress.init_size (size_);
    errno_assert (rc != -1);
    memcpy (in_progress.data (), data_, size_);
    bytes_used_ = size_;
    return 1;
}
