/* SPDX-License-Identifier: MPL-2.0 */

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
