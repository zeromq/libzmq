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

#include "ipc_address.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include "err.hpp"

#include <string>
#include <sstream>

zmq::ipc_address_t::ipc_address_t ()
{
    memset (&address, 0, sizeof (address));
}

zmq::ipc_address_t::ipc_address_t (const sockaddr *sa, socklen_t sa_len)
{
    zmq_assert(sa && sa_len > 0);

    memset (&address, 0, sizeof (address));
    if (sa->sa_family == AF_UNIX) {
        memcpy(&address, sa, sa_len);
    }
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
#if defined ZMQ_HAVE_LINUX
    if (path_[0] == '@' && !path_[1]) {
            errno = EINVAL;
            return -1;
    }
#endif

    address.sun_family = AF_UNIX;
    strcpy (address.sun_path, path_);
#if defined ZMQ_HAVE_LINUX
    /* Abstract sockets on Linux start with '\0' */
    if (path_[0] == '@')
        *address.sun_path = '\0';
#endif
    return 0;
}

int zmq::ipc_address_t::to_string (std::string &addr_)
{
    if (address.sun_family != AF_UNIX) {
        addr_.clear ();
        return -1;
    }

    std::stringstream s;
#if !defined ZMQ_HAVE_LINUX
    s << "ipc://" << address.sun_path;
#else
    s << "ipc://";
    if (!address.sun_path[0] && address.sun_path[1])
       s << "@" << address.sun_path + 1;
    else
       s << address.sun_path;
#endif
    addr_ = s.str ();
    return 0;
}

const sockaddr *zmq::ipc_address_t::addr () const
{
    return (sockaddr*) &address;
}

socklen_t zmq::ipc_address_t::addrlen () const
{
#if defined ZMQ_HAVE_LINUX
    if (!address.sun_path[0] && address.sun_path[1])
        return (socklen_t) strlen(address.sun_path + 1) + sizeof (sa_family_t) + 1;
#endif
    return (socklen_t) sizeof (address);
}

#endif
