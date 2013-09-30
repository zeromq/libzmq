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
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "gssapi_mechanism_base.hpp"
#include "wire.hpp"

zmq::gssapi_mechanism_base_t::gssapi_mechanism_base_t () :
    gss_continue_needed (false)
{
}

zmq::gssapi_mechanism_base_t::~gssapi_mechanism_base_t ()
{
}

int zmq::gssapi_mechanism_base_t::produce_token (msg_t *msg_) const
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add command name
    memcpy (ptr, "\x05TOKEN", 6);
    ptr += 6;

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    return 0;
}

int zmq::gssapi_mechanism_base_t::process_token (msg_t *msg_)
{
    const unsigned char *ptr = static_cast <unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    if (bytes_left < 6 || memcmp (ptr, "\x05TOKEN", 6)) {
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;

    return 0;
}

