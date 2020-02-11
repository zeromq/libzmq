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
#include <string>
#include <sstream>

#include "macros.hpp"
#include "ws_address.hpp"
#include "stdint.hpp"
#include "err.hpp"
#include "ip.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#endif

#include <limits.h>

zmq::ws_address_t::ws_address_t ()
{
    memset (&_address, 0, sizeof (_address));
}

zmq::ws_address_t::ws_address_t (const sockaddr *sa_, socklen_t sa_len_)
{
    zmq_assert (sa_ && sa_len_ > 0);

    memset (&_address, 0, sizeof (_address));
    if (sa_->sa_family == AF_INET
        && sa_len_ >= static_cast<socklen_t> (sizeof (_address.ipv4)))
        memcpy (&_address.ipv4, sa_, sizeof (_address.ipv4));
    else if (sa_->sa_family == AF_INET6
             && sa_len_ >= static_cast<socklen_t> (sizeof (_address.ipv6)))
        memcpy (&_address.ipv6, sa_, sizeof (_address.ipv6));

    _path = std::string ("");

    char hbuf[NI_MAXHOST];
    const int rc = getnameinfo (addr (), addrlen (), hbuf, sizeof (hbuf), NULL,
                                0, NI_NUMERICHOST);
    if (rc != 0) {
        _host = std::string ("localhost");
        return;
    }

    std::ostringstream os;

    if (_address.family () == AF_INET6)
        os << std::string ("[");

    os << std::string (hbuf);

    if (_address.family () == AF_INET6)
        os << std::string ("]");

    _host = os.str ();
}

int zmq::ws_address_t::resolve (const char *name_, bool local_, bool ipv6_)
{
    //  find the host part, It's important to use str*r*chr to only get
    //  the latest colon since IPv6 addresses use colons as delemiters.
    const char *delim = strrchr (name_, ':');
    if (delim == NULL) {
        errno = EINVAL;
        return -1;
    }
    _host = std::string (name_, delim - name_);

    // find the path part, which is optional
    delim = strrchr (name_, '/');
    std::string host_name;
    if (delim) {
        _path = std::string (delim);
        // remove the path, otherwise resolving the port will fail with wildcard
        host_name = std::string (name_, delim - name_);
    } else {
        _path = std::string ("/");
        host_name = name_;
    }

    ip_resolver_options_t resolver_opts;
    resolver_opts.bindable (local_)
      .allow_dns (!local_)
      .allow_nic_name (local_)
      .ipv6 (ipv6_)
      .allow_path (true)
      .expect_port (true);

    ip_resolver_t resolver (resolver_opts);

    return resolver.resolve (&_address, host_name.c_str ());
}

int zmq::ws_address_t::to_string (std::string &addr_) const
{
    std::ostringstream os;
    os << std::string ("ws://") << host () << std::string (":")
       << _address.port () << _path;
    addr_ = os.str ();

    return 0;
}

const sockaddr *zmq::ws_address_t::addr () const
{
    return _address.as_sockaddr ();
}

socklen_t zmq::ws_address_t::addrlen () const
{
    return _address.sockaddr_len ();
}

const char *zmq::ws_address_t::host () const
{
    return _host.c_str ();
}

const char *zmq::ws_address_t::path () const
{
    return _path.c_str ();
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::ws_address_t::family () const
#else
sa_family_t zmq::ws_address_t::family () const
#endif
{
    return _address.family ();
}
