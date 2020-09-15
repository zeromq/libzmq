/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#include "precompiled.hpp"
#include "compat.hpp"
#include "ipc_address.hpp"

#if defined ZMQ_HAVE_IPC

#include "err.hpp"

#include <string>

zmq::ipc_address_t::ipc_address_t ()
{
    memset (&_address, 0, sizeof _address);
}

zmq::ipc_address_t::ipc_address_t (const sockaddr *sa_, socklen_t sa_len_) :
    _addrlen (sa_len_)
{
    zmq_assert (sa_ && sa_len_ > 0);

    memset (&_address, 0, sizeof _address);
    if (sa_->sa_family == AF_UNIX)
        memcpy (&_address, sa_, sa_len_);
}

zmq::ipc_address_t::~ipc_address_t ()
{
}

int zmq::ipc_address_t::resolve (const char *path_)
{
    const size_t path_len = strlen (path_);
    if (path_len >= sizeof _address.sun_path) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (path_[0] == '@' && !path_[1]) {
        errno = EINVAL;
        return -1;
    }

    _address.sun_family = AF_UNIX;
    memcpy (_address.sun_path, path_, path_len + 1);
    /* Abstract sockets start with '\0' */
    if (path_[0] == '@')
        *_address.sun_path = '\0';

    _addrlen =
      static_cast<socklen_t> (offsetof (sockaddr_un, sun_path) + path_len);
    return 0;
}

int zmq::ipc_address_t::to_string (std::string &addr_) const
{
    if (_address.sun_family != AF_UNIX) {
        addr_.clear ();
        return -1;
    }

    const char prefix[] = "ipc://";
    char buf[sizeof prefix + sizeof _address.sun_path];
    char *pos = buf;
    memcpy (pos, prefix, sizeof prefix - 1);
    pos += sizeof prefix - 1;
    const char *src_pos = _address.sun_path;
    if (!_address.sun_path[0] && _address.sun_path[1]) {
        *pos++ = '@';
        src_pos++;
    }
    // according to http://man7.org/linux/man-pages/man7/unix.7.html, NOTES
    // section, address.sun_path might not always be null-terminated; therefore,
    // we calculate the length based of addrlen
    const size_t src_len =
      strnlen (src_pos, _addrlen - offsetof (sockaddr_un, sun_path)
                          - (src_pos - _address.sun_path));
    memcpy (pos, src_pos, src_len);
    addr_.assign (buf, pos - buf + src_len);
    return 0;
}

const sockaddr *zmq::ipc_address_t::addr () const
{
    return reinterpret_cast<const sockaddr *> (&_address);
}

socklen_t zmq::ipc_address_t::addrlen () const
{
    return _addrlen;
}

#endif
