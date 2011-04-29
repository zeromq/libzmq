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

#include <string.h>

#include "uuid.hpp"
#include "err.hpp"
#include "stdint.hpp"
#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS

#include <rpc.h>

void zmq::generate_uuid (void *buf_)
{
    RPC_STATUS ret = UuidCreate ((::UUID*) buf_);
    zmq_assert (ret == RPC_S_OK);
}

#elif defined ZMQ_HAVE_FREEBSD || defined ZMQ_HAVE_NETBSD

#include <uuid.h>

void zmq::generate_uuid (void *buf_)
{
    uint32_t status;
    uuid_create ((::uuid_t*) buf_, &status);
    zmq_assert (status == uuid_s_ok);
}

#elif defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_SOLARIS ||\
      defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_CYGWIN

#include <uuid/uuid.h>

void zmq::generate_uuid (void *buf_)
{
    uuid_generate ((unsigned char*) buf_);
}

#elif defined ZMQ_HAVE_OPENVMS

#include <starlet.h>

void zmq::generate_uuid (void *buf_)
{
    sys$create_uid(buf_);
}

#else

#include <openssl/rand.h>

void zmq::generate_uuid (void *buf_)
{
    unsigned char *buf = (unsigned char*) buf_;

    //  Generate random value.
    int ret = RAND_bytes (buf, 16);
    zmq_assert (ret == 1);

    //  Set UUID variant to 2 (UUID as specified in RFC4122).
    const unsigned char variant = 2;
    buf [8] = (buf [8] & 0x3f) | (variant << 6);

    //  Set UUID version to 4 (randomly or pseudo-randomly generated UUID).
    const unsigned char version = 4;
    buf [6] = (buf [6] & 0x0f) | (version << 4);
}

#endif

