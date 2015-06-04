/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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
