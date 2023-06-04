/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_ADDRESS_HPP_INCLUDED__
#define __ZMQ_WS_ADDRESS_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "ip_resolver.hpp"

namespace zmq
{
class ws_address_t
{
  public:
    ws_address_t ();
    ws_address_t (const sockaddr *sa_, socklen_t sa_len_);

    //  This function translates textual WS address into an address
    //  structure. If 'local' is true, names are resolved as local interface
    //  names. If it is false, names are resolved as remote hostnames.
    //  If 'ipv6' is true, the name may resolve to IPv6 address.
    int resolve (const char *name_, bool local_, bool ipv6_);

    //  The opposite to resolve()
    int to_string (std::string &addr_) const;

#if defined ZMQ_HAVE_WINDOWS
    unsigned short family () const;
#else
    sa_family_t family () const;
#endif
    const sockaddr *addr () const;
    socklen_t addrlen () const;

    const char *host () const;
    const char *path () const;

  protected:
    ip_addr_t _address;

  private:
    std::string _host;
    std::string _path;
};
}

#endif
