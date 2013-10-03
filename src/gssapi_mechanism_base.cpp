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

zmq::gssapi_mechanism_base_t::gssapi_mechanism_base_t ()
{
}

zmq::gssapi_mechanism_base_t::~gssapi_mechanism_base_t ()
{
}

int zmq::gssapi_mechanism_base_t::produce_token (msg_t *msg_, int flags_, void *token_value_, size_t token_length_)
{
    zmq_assert (token_value_);
    zmq_assert (token_length_ <= 0xFFFFFFFFUL);

    const size_t cmd_len = 6 + 1 + 4 + token_length_;
    uint8_t *cmd_buf = static_cast <uint8_t *> (malloc (cmd_len));
    alloc_assert (cmd_buf);

    uint8_t *ptr = cmd_buf;

    //  Add command name
    memcpy (ptr, "\x05TOKEN", 6);
    ptr += 6;

    // Add gss flags
    put_uint8 (ptr, static_cast <uint8_t> (flags_));
    ptr += 1;

    // Add token length
    put_uint32 (ptr, static_cast <uint32_t> (token_length_));
    ptr += 4;

    // Add token value
    memcpy (ptr, token_value_, token_length_);
    ptr += token_length_;

    const int rc = msg_->init_size (cmd_len);
    errno_assert (rc == 0);
    memcpy (msg_->data (), cmd_buf, cmd_len);
    free (cmd_buf);

    return 0;
}

int zmq::gssapi_mechanism_base_t::process_token (msg_t *msg_, int &flags_, void **token_value_, size_t &token_length_)
{
    zmq_assert (token_value_);

    uint8_t *ptr = static_cast <uint8_t *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    // Get command name
    if (bytes_left < 6 || memcmp (ptr, "\x05TOKEN", 6)) {
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;
 
    // Get flags
    if (bytes_left < 1) {
        errno = EPROTO;
        return -1;
    }
    flags_ = static_cast <int> (get_uint8 (ptr));
    ptr += 1;
    bytes_left -= 1;

    // Get token length
    if (bytes_left < 4) {
        errno = EPROTO;
        return -1;
    }
    token_length_ = get_uint32 (ptr);
    ptr += 4;
    bytes_left -= 4;
    
    // Get token value
    if (bytes_left < token_length_) {
        errno = EPROTO;
        return -1;
    }
    *token_value_ = static_cast <char *> (malloc (token_length_ ? token_length_ : 1));
    if (token_length_) {
        alloc_assert (*token_value_);
        memcpy(*token_value_, ptr, token_length_);
        ptr += token_length_;
        bytes_left -= token_length_;
    }

    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }

    return 0;
}

