/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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
#include <string>

#include "tcp_address.hpp"
#include "platform.hpp"
#include "stdint.hpp"
#include "err.hpp"
#include "ip.hpp"

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#endif

//  Some platforms (notably Darwin/OSX and NetBSD) do not define all AI_
//  flags for getaddrinfo(). This can be worked around safely by defining
//  these to 0.
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0
#endif

#if defined ZMQ_HAVE_SOLARIS

#include <sys/sockio.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>

//  On Solaris platform, network interface name can be queried by ioctl.
int zmq::tcp_address_t::resolve_nic_name (const char *nic_, bool ipv4only_)
{
    //  TODO: Unused parameter, IPv6 support not implemented for Solaris.
    (void) ipv4only_;

    //  Create a socket.
    int fd = open_socket (AF_INET, SOCK_DGRAM, 0);
    zmq_assert (fd != -1);

    //  Retrieve number of interfaces.
    lifnum ifn;
    ifn.lifn_family = AF_INET;
    ifn.lifn_flags = 0;
    int rc = ioctl (fd, SIOCGLIFNUM, (char*) &ifn);
    zmq_assert (rc != -1);

    //  Allocate memory to get interface names.
    size_t ifr_size = sizeof (struct lifreq) * ifn.lifn_count;
    char *ifr = (char*) malloc (ifr_size);
    alloc_assert (ifr);
    
    //  Retrieve interface names.
    lifconf ifc;
    ifc.lifc_family = AF_INET;
    ifc.lifc_flags = 0;
    ifc.lifc_len = ifr_size;
    ifc.lifc_buf = ifr;
    rc = ioctl (fd, SIOCGLIFCONF, (char*) &ifc);
    zmq_assert (rc != -1);

    //  Find the interface with the specified name and AF_INET family.
    bool found = false;
    lifreq *ifrp = ifc.lifc_req;
    for (int n = 0; n < (int) (ifc.lifc_len / sizeof (lifreq));
          n ++, ifrp ++) {
        if (!strcmp (nic_, ifrp->lifr_name)) {
            rc = ioctl (fd, SIOCGLIFADDR, (char*) ifrp);
            zmq_assert (rc != -1);
            if (ifrp->lifr_addr.ss_family == AF_INET) {
                address.ipv4 = *(sockaddr_in*) &ifrp->lifr_addr;
                found = true;
                break;
            }
        }
    }

    //  Clean-up.
    free (ifr);
    close (fd);

    if (!found) {
        errno = ENODEV;
        return -1;
    }

    return 0;
}

#elif defined ZMQ_HAVE_AIX || defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_ANDROID

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

int zmq::tcp_address_t::resolve_nic_name (const char *nic_, bool ipv4only_)
{
    //  TODO: Unused parameter, IPv6 support not implemented for AIX or HP/UX.
    (void) ipv4only_;

    //  Create a socket.
    int sd = open_socket (AF_INET, SOCK_DGRAM, 0);
    zmq_assert (sd != -1);

    struct ifreq ifr; 

    //  Copy interface name for ioctl get.
    strncpy (ifr.ifr_name, nic_, sizeof (ifr.ifr_name));

    //  Fetch interface address.
    int rc = ioctl (sd, SIOCGIFADDR, (caddr_t) &ifr, sizeof (struct ifreq));

    //  Clean up.
    close (sd);

    if (rc == -1) {
        errno = ENODEV;
        return -1;
    }

    memcpy (&address.ipv4.sin_addr, &((sockaddr_in*) &ifr.ifr_addr)->sin_addr,
        sizeof (in_addr));

    return 0;    
}

#elif ((defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_OPENBSD ||\
    defined ZMQ_HAVE_QNXNTO || defined ZMQ_HAVE_NETBSD)\
    && defined ZMQ_HAVE_IFADDRS)

#include <ifaddrs.h>

//  On these platforms, network interface name can be queried
//  using getifaddrs function.
int zmq::tcp_address_t::resolve_nic_name (const char *nic_, bool ipv4only_)
{
    //  Get the addresses.
    ifaddrs* ifa = NULL;
    int rc = getifaddrs (&ifa);
    zmq_assert (rc == 0);    
    zmq_assert (ifa != NULL);

    //  Find the corresponding network interface.
    bool found = false;
    for (ifaddrs *ifp = ifa; ifp != NULL ;ifp = ifp->ifa_next)
    {
        if (ifp->ifa_addr == NULL)
            continue;

        int family = ifp->ifa_addr->sa_family;

        if ((family == AF_INET
             || (!ipv4only_ && family == AF_INET6))
            && !strcmp (nic_, ifp->ifa_name))
        {
            memcpy (&address, ifp->ifa_addr,
                    (family == AF_INET) ? sizeof (struct sockaddr_in)
                                        : sizeof (struct sockaddr_in6));
            found = true;
            break;
        }
    }

    //  Clean-up;
    freeifaddrs (ifa);

    if (!found) {
        errno = ENODEV;
        return -1;
    }

    return 0;
}

#else

//  On other platforms we assume there are no sane interface names.
//  This is true especially of Windows.
int zmq::tcp_address_t::resolve_nic_name (const char *nic_, bool ipv4only_)
{
    //  All unused parameters.
    (void) nic_;
    (void) ipv4only_;

    errno = ENODEV;
    return -1;
}

#endif

int zmq::tcp_address_t::resolve_interface (char const *interface_,
    bool ipv4only_)
{
    //  Initialize temporary output pointers with storage address.
    sockaddr_storage ss;
    sockaddr *out_addr = (sockaddr *) &ss;
    socklen_t out_addrlen;

    //  Initialise IP-format family/port and populate temporary output pointers
    //  with the address.
    if (ipv4only_) {
        sockaddr_in ip4_addr;
        memset (&ip4_addr, 0, sizeof (ip4_addr));
        ip4_addr.sin_family = AF_INET;
        ip4_addr.sin_addr.s_addr = htonl (INADDR_ANY);
        out_addrlen = (socklen_t) sizeof (ip4_addr);
        memcpy (out_addr, &ip4_addr, out_addrlen);
    } else {
        sockaddr_in6 ip6_addr;
        memset (&ip6_addr, 0, sizeof (ip6_addr));
        ip6_addr.sin6_family = AF_INET6;
        memcpy (&ip6_addr.sin6_addr, &in6addr_any, sizeof (in6addr_any));
        out_addrlen = (socklen_t) sizeof (ip6_addr);
        memcpy (out_addr, &ip6_addr, out_addrlen);
    }

    //  * resolves to INADDR_ANY or in6addr_any.
    if (strcmp (interface_, "*") == 0) {
        zmq_assert (out_addrlen <= (socklen_t) sizeof (address));
        memcpy (&address, out_addr, out_addrlen);
        return 0;
    }

    //  Try to resolve the string as a NIC name.
    int rc = resolve_nic_name (interface_, ipv4only_);
    if (rc != 0 && errno != ENODEV)
        return rc;
    if (rc == 0) {
        zmq_assert (out_addrlen <= (socklen_t) sizeof (address));
        memcpy (&address, out_addr, out_addrlen);
        return 0;
    }

    //  There's no such interface name. Assume literal address.
#if defined ZMQ_HAVE_OPENVMS && defined __ia64
    __addrinfo64 *res = NULL;
    __addrinfo64 req;
#else
    addrinfo *res = NULL;
    addrinfo req;
#endif
    memset (&req, 0, sizeof (req));

    //  Choose IPv4 or IPv6 protocol family. Note that IPv6 allows for
    //  IPv4-in-IPv6 addresses.
    req.ai_family = ipv4only_ ? AF_INET : AF_INET6;

    //  Arbitrary, not used in the output, but avoids duplicate results.
    req.ai_socktype = SOCK_STREAM;

    //  Restrict hostname/service to literals to avoid any DNS lookups or
    //  service-name irregularity due to indeterminate socktype.
    req.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

#ifndef ZMQ_HAVE_WINDOWS
    //  Windows by default maps IPv4 addresses into IPv6. In this API we only
    //  require IPv4-mapped addresses when no native IPv6 interfaces are
    //  available (~AI_ALL).  This saves an additional DNS roundtrip for IPv4
    //  addresses.
    if (req.ai_family == AF_INET6)
        req.ai_flags |= AI_V4MAPPED;
#endif

    //  Resolve the literal address. Some of the error info is lost in case
    //  of error, however, there's no way to report EAI errors via errno.
    rc = getaddrinfo (interface_, NULL, &req, &res);
    if (rc) {
        errno = ENODEV;
        return -1;
    }

    //  Use the first result.
    zmq_assert ((size_t) (res->ai_addrlen) <= sizeof (address));
    memcpy (&address, res->ai_addr, res->ai_addrlen);

    //  Cleanup getaddrinfo after copying the possibly referenced result.
    if (res)
        freeaddrinfo (res);

    return 0;
}

int zmq::tcp_address_t::resolve_hostname (const char *hostname_, bool ipv4only_)
{
    //  Set up the query.
#if defined ZMQ_HAVE_OPENVMS && defined __ia64 && __INITIAL_POINTER_SIZE == 64
    __addrinfo64 req;
#else
    addrinfo req;
#endif
    memset (&req, 0, sizeof (req));

    //  Choose IPv4 or IPv6 protocol family. Note that IPv6 allows for
    //  IPv4-in-IPv6 addresses.
    req.ai_family = ipv4only_ ? AF_INET : AF_INET6;

    //  Need to choose one to avoid duplicate results from getaddrinfo() - this
    //  doesn't really matter, since it's not included in the addr-output.
    req.ai_socktype = SOCK_STREAM;
    
#ifndef ZMQ_HAVE_WINDOWS
    //  Windows by default maps IPv4 addresses into IPv6. In this API we only
    //  require IPv4-mapped addresses when no native IPv6 interfaces are
    //  available.  This saves an additional DNS roundtrip for IPv4 addresses.
    if (req.ai_family == AF_INET6)
        req.ai_flags |= AI_V4MAPPED;
#endif

    //  Resolve host name. Some of the error info is lost in case of error,
    //  however, there's no way to report EAI errors via errno.
#if defined ZMQ_HAVE_OPENVMS && defined __ia64 && __INITIAL_POINTER_SIZE == 64
    __addrinfo64 *res;
#else
    addrinfo *res;
#endif
    int rc = getaddrinfo (hostname_, NULL, &req, &res);
    if (rc) {
        switch (rc) {
        case EAI_MEMORY:
            errno = ENOMEM;
            break;
        default:
            errno = EINVAL;
            break;
        }
        return -1;
    }

    //  Copy first result to output addr with hostname and service.
    zmq_assert ((size_t) (res->ai_addrlen) <= sizeof (address));
    memcpy (&address, res->ai_addr, res->ai_addrlen);
 
    freeaddrinfo (res);
    
    return 0;
}

zmq::tcp_address_t::tcp_address_t ()
{
    memset (&address, 0, sizeof (address));
}

zmq::tcp_address_t::~tcp_address_t ()
{
}

int zmq::tcp_address_t::resolve (const char *name_, bool local_, bool ipv4only_)
{
    //  Find the ':' at end that separates address from the port number.
    const char *delimiter = strrchr (name_, ':');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //  Separate the address/port.
    std::string addr_str (name_, delimiter - name_);
    std::string port_str (delimiter + 1);

    //  Remove square brackets around the address, if any.
    if (!addr_str.empty () && addr_str [0] == '[' &&
          addr_str [addr_str.size () - 1] == ']')
        addr_str = addr_str.substr (1, addr_str.size () - 2);

    //  Parse the port number (0 is not a valid port).
    uint16_t port = (uint16_t) atoi (port_str.c_str());
    if (port == 0) {
        errno = EINVAL;
        return -1;
    }

    //  Resolve the IP address.
    int rc;
    if (local_)
        rc = resolve_interface (addr_str.c_str (), ipv4only_);
    else
        rc = resolve_hostname (addr_str.c_str (), ipv4only_);
    if (rc != 0)
        return -1;

    //  Set the port into the address structure.
    if (address.generic.sa_family == AF_INET6)
        address.ipv6.sin6_port = htons (port);
    else
        address.ipv4.sin_port = htons (port);

    return 0;
}

sockaddr *zmq::tcp_address_t::addr ()
{
    return &address.generic;
}

socklen_t zmq::tcp_address_t::addrlen ()
{
    if (address.generic.sa_family == AF_INET6)
        return (socklen_t) sizeof (address.ipv6);
    else
        return (socklen_t) sizeof (address.ipv4);
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::tcp_address_t::family ()
#else
sa_family_t zmq::tcp_address_t::family ()
#endif
{
    return address.generic.sa_family;
}

