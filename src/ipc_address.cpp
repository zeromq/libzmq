/*
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2011 Other contributors as noted in the AUTHORS file

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

#include "ipc_address.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include "err.hpp"

#include <string.h>

zmq::ipc_address_t::ipc_address_t ()
{
    memset (&address, 0, sizeof (address));
}

zmq::ipc_address_t::~ipc_address_t ()
{
}

int zmq::ipc_address_t::resolve (const char *path_)
{
    if (strlen (path_) >= sizeof (address.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    address.sun_family = AF_UNIX;
    strcpy (address.sun_path, path_);
    return 0;
}

sockaddr *zmq::ipc_address_t::addr ()
{
    return (sockaddr*) &address;
}

socklen_t zmq::ipc_address_t::addrlen ()
{
    return (socklen_t) sizeof (address);
}

#endif
