/* SPDX-License-Identifier: MPL-2.0 */

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
