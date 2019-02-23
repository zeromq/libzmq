#include "precompiled.hpp"
#include <string>
#include <cstring>

#include "macros.hpp"
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

#include "ip_resolver.hpp"

int zmq::ip_addr_t::family () const
{
    return generic.sa_family;
}

bool zmq::ip_addr_t::is_multicast () const
{
    if (family () == AF_INET) {
        //  IPv4 Multicast: address MSBs are 1110
        //  Range: 224.0.0.0 - 239.255.255.255
        return IN_MULTICAST (ntohl (ipv4.sin_addr.s_addr));
    }
    //  IPv6 Multicast: ff00::/8
    return IN6_IS_ADDR_MULTICAST (&ipv6.sin6_addr) != 0;
}

uint16_t zmq::ip_addr_t::port () const
{
    if (family () == AF_INET6) {
        return ntohs (ipv6.sin6_port);
    }
    return ntohs (ipv4.sin_port);
}

const struct sockaddr *zmq::ip_addr_t::as_sockaddr () const
{
    return &generic;
}

zmq::zmq_socklen_t zmq::ip_addr_t::sockaddr_len () const
{
    return static_cast<zmq_socklen_t> (family () == AF_INET6 ? sizeof (ipv6)
                                                             : sizeof (ipv4));
}

void zmq::ip_addr_t::set_port (uint16_t port_)
{
    if (family () == AF_INET6) {
        ipv6.sin6_port = htons (port_);
    } else {
        ipv4.sin_port = htons (port_);
    }
}

//  Construct an "ANY" address for the given family
zmq::ip_addr_t zmq::ip_addr_t::any (int family_)
{
    ip_addr_t addr;

    if (family_ == AF_INET) {
        sockaddr_in *ip4_addr = &addr.ipv4;
        memset (ip4_addr, 0, sizeof (*ip4_addr));
        ip4_addr->sin_family = AF_INET;
        ip4_addr->sin_addr.s_addr = htonl (INADDR_ANY);
    } else if (family_ == AF_INET6) {
        sockaddr_in6 *ip6_addr = &addr.ipv6;

        memset (ip6_addr, 0, sizeof (*ip6_addr));
        ip6_addr->sin6_family = AF_INET6;
#ifdef ZMQ_HAVE_VXWORKS
        struct in6_addr newaddr = IN6ADDR_ANY_INIT;
        memcpy (&ip6_addr->sin6_addr, &newaddr, sizeof (in6_addr));
#else
        memcpy (&ip6_addr->sin6_addr, &in6addr_any, sizeof (in6addr_any));
#endif
    } else {
        assert (0 == "unsupported address family");
    }

    return addr;
}

zmq::ip_resolver_options_t::ip_resolver_options_t () :
    _bindable_wanted (false),
    _nic_name_allowed (false),
    _ipv6_wanted (false),
    _port_expected (false),
    _dns_allowed (false)
{
}

zmq::ip_resolver_options_t &
zmq::ip_resolver_options_t::bindable (bool bindable_)
{
    _bindable_wanted = bindable_;

    return *this;
}

zmq::ip_resolver_options_t &
zmq::ip_resolver_options_t::allow_nic_name (bool allow_)
{
    _nic_name_allowed = allow_;

    return *this;
}

zmq::ip_resolver_options_t &zmq::ip_resolver_options_t::ipv6 (bool ipv6_)
{
    _ipv6_wanted = ipv6_;

    return *this;
}

//  If true we expect that the host will be followed by a colon and a port
//  number or service name
zmq::ip_resolver_options_t &
zmq::ip_resolver_options_t::expect_port (bool expect_)
{
    _port_expected = expect_;

    return *this;
}

zmq::ip_resolver_options_t &zmq::ip_resolver_options_t::allow_dns (bool allow_)
{
    _dns_allowed = allow_;

    return *this;
}

bool zmq::ip_resolver_options_t::bindable ()
{
    return _bindable_wanted;
}

bool zmq::ip_resolver_options_t::allow_nic_name ()
{
    return _nic_name_allowed;
}

bool zmq::ip_resolver_options_t::ipv6 ()
{
    return _ipv6_wanted;
}

bool zmq::ip_resolver_options_t::expect_port ()
{
    return _port_expected;
}

bool zmq::ip_resolver_options_t::allow_dns ()
{
    return _dns_allowed;
}

zmq::ip_resolver_t::ip_resolver_t (ip_resolver_options_t opts_) :
    _options (opts_)
{
}

int zmq::ip_resolver_t::resolve (ip_addr_t *ip_addr_, const char *name_)
{
    std::string addr;
    uint16_t port;

    if (_options.expect_port ()) {
        //  We expect 'addr:port'. It's important to use str*r*chr to only get
        //  the latest colon since IPv6 addresses use colons as delemiters.
        const char *delim = strrchr (name_, ':');

        if (delim == NULL) {
            errno = EINVAL;
            return -1;
        }

        addr = std::string (name_, delim - name_);
        std::string port_str = std::string (delim + 1);

        if (port_str == "*") {
            if (_options.bindable ()) {
                //  Resolve wildcard to 0 to allow autoselection of port
                port = 0;
            } else {
                errno = EINVAL;
                return -1;
            }
        } else if (port_str == "0") {
            //  Using "0" for a bind address is equivalent to using "*". For a
            //  connectable address it could be used to connect to port 0.
            port = 0;
        } else {
            //  Parse the port number (0 is not a valid port).
            port = static_cast<uint16_t> (atoi (port_str.c_str ()));
            if (port == 0) {
                errno = EINVAL;
                return -1;
            }
        }
    } else {
        addr = std::string (name_);
        port = 0;
    }

    //  Trim any square brackets surrounding the address. Used for
    //  IPv6 addresses to remove the confusion with the port
    //  delimiter.
    //  TODO Should we validate that the brackets are present if
    //  'addr' contains ':' ?
    const size_t brackets_length = 2;
    if (addr.size () >= brackets_length && addr[0] == '['
        && addr[addr.size () - 1] == ']') {
        addr = addr.substr (1, addr.size () - brackets_length);
    }

    //  Look for an interface name / zone_id in the address
    //  Reference: https://tools.ietf.org/html/rfc4007
    std::size_t pos = addr.rfind ('%');
    uint32_t zone_id = 0;

    if (pos != std::string::npos) {
        std::string if_str = addr.substr (pos + 1);
        addr = addr.substr (0, pos);

        if (isalpha (if_str.at (0))) {
            zone_id = do_if_nametoindex (if_str.c_str ());
        } else {
            zone_id = static_cast<uint32_t> (atoi (if_str.c_str ()));
        }

        if (zone_id == 0) {
            errno = EINVAL;
            return -1;
        }
    }

    bool resolved = false;
    const char *addr_str = addr.c_str ();

    if (_options.bindable () && addr == "*") {
        //  Return an ANY address
        *ip_addr_ = ip_addr_t::any (_options.ipv6 () ? AF_INET6 : AF_INET);
        resolved = true;
    }

    if (!resolved && _options.allow_nic_name ()) {
        //  Try to resolve the string as a NIC name.
        int rc = resolve_nic_name (ip_addr_, addr_str);

        if (rc == 0) {
            resolved = true;
        } else if (errno != ENODEV) {
            return rc;
        }
    }

    if (!resolved) {
        int rc = resolve_getaddrinfo (ip_addr_, addr_str);

        if (rc != 0) {
            return rc;
        }
        resolved = true;
    }

    //  Store the port into the structure. We could get 'getaddrinfo' to do it
    //  for us but since we don't resolve service names it's a bit overkill and
    //  we'd still have to do it manually when the address is resolved by
    //  'resolve_nic_name'
    ip_addr_->set_port (port);

    if (ip_addr_->family () == AF_INET6) {
        ip_addr_->ipv6.sin6_scope_id = zone_id;
    }

    assert (resolved == true);
    return 0;
}

int zmq::ip_resolver_t::resolve_getaddrinfo (ip_addr_t *ip_addr_,
                                             const char *addr_)
{
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
    req.ai_family = _options.ipv6 () ? AF_INET6 : AF_INET;

    //  Arbitrary, not used in the output, but avoids duplicate results.
    req.ai_socktype = SOCK_STREAM;

    req.ai_flags = 0;

    if (_options.bindable ()) {
        req.ai_flags |= AI_PASSIVE;
    }

    if (!_options.allow_dns ()) {
        req.ai_flags |= AI_NUMERICHOST;
    }

#if defined AI_V4MAPPED
    //  In this API we only require IPv4-mapped addresses when
    //  no native IPv6 interfaces are available (~AI_ALL).
    //  This saves an additional DNS roundtrip for IPv4 addresses.
    if (req.ai_family == AF_INET6) {
        req.ai_flags |= AI_V4MAPPED;
    }
#endif

    //  Resolve the literal address. Some of the error info is lost in case
    //  of error, however, there's no way to report EAI errors via errno.
    int rc = do_getaddrinfo (addr_, NULL, &req, &res);

#if defined AI_V4MAPPED
    // Some OS do have AI_V4MAPPED defined but it is not supported in getaddrinfo()
    // returning EAI_BADFLAGS. Detect this and retry
    if (rc == EAI_BADFLAGS && (req.ai_flags & AI_V4MAPPED)) {
        req.ai_flags &= ~AI_V4MAPPED;
        rc = do_getaddrinfo (addr_, NULL, &req, &res);
    }
#endif

#if defined ZMQ_HAVE_WINDOWS
    //  Resolve specific case on Windows platform when using IPv4 address
    //  with ZMQ_IPv6 socket option.
    if ((req.ai_family == AF_INET6) && (rc == WSAHOST_NOT_FOUND)) {
        req.ai_family = AF_INET;
        rc = do_getaddrinfo (addr_, NULL, &req, &res);
    }
#endif

    if (rc) {
        switch (rc) {
            case EAI_MEMORY:
                errno = ENOMEM;
                break;
            default:
                if (_options.bindable ()) {
                    errno = ENODEV;
                } else {
                    errno = EINVAL;
                }
                break;
        }
        return -1;
    }

    //  Use the first result.
    zmq_assert (res != NULL);
    zmq_assert ((size_t) res->ai_addrlen <= sizeof (*ip_addr_));
    memcpy (ip_addr_, res->ai_addr, res->ai_addrlen);

    //  Cleanup getaddrinfo after copying the possibly referenced result.
    do_freeaddrinfo (res);

    return 0;
}

#ifdef ZMQ_HAVE_SOLARIS
#include <sys/sockio.h>

//  On Solaris platform, network interface name can be queried by ioctl.
int zmq::ip_resolver_t::resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_)
{
    //  Create a socket.
    const int fd = open_socket (AF_INET, SOCK_DGRAM, 0);
    errno_assert (fd != -1);

    //  Retrieve number of interfaces.
    lifnum ifn;
    ifn.lifn_family = AF_INET;
    ifn.lifn_flags = 0;
    int rc = ioctl (fd, SIOCGLIFNUM, (char *) &ifn);
    errno_assert (rc != -1);

    //  Allocate memory to get interface names.
    const size_t ifr_size = sizeof (struct lifreq) * ifn.lifn_count;
    char *ifr = (char *) malloc (ifr_size);
    alloc_assert (ifr);

    //  Retrieve interface names.
    lifconf ifc;
    ifc.lifc_family = AF_INET;
    ifc.lifc_flags = 0;
    ifc.lifc_len = ifr_size;
    ifc.lifc_buf = ifr;
    rc = ioctl (fd, SIOCGLIFCONF, (char *) &ifc);
    errno_assert (rc != -1);

    //  Find the interface with the specified name and AF_INET family.
    bool found = false;
    lifreq *ifrp = ifc.lifc_req;
    for (int n = 0; n < (int) (ifc.lifc_len / sizeof (lifreq)); n++, ifrp++) {
        if (!strcmp (nic_, ifrp->lifr_name)) {
            rc = ioctl (fd, SIOCGLIFADDR, (char *) ifrp);
            errno_assert (rc != -1);
            if (ifrp->lifr_addr.ss_family == AF_INET) {
                ip_addr_->ipv4 = *(sockaddr_in *) &ifrp->lifr_addr;
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

#elif defined ZMQ_HAVE_AIX || defined ZMQ_HAVE_HPUX                            \
  || defined ZMQ_HAVE_ANDROID || defined ZMQ_HAVE_VXWORKS
#include <sys/ioctl.h>
#ifdef ZMQ_HAVE_VXWORKS
#include <ioLib.h>
#endif

int zmq::ip_resolver_t::resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_)
{
#if defined ZMQ_HAVE_AIX || defined ZMQ_HAVE_HPUX
    // IPv6 support not implemented for AIX or HP/UX.
    if (_options.ipv6 ()) {
        errno = ENODEV;
        return -1;
    }
#endif

    //  Create a socket.
    const int sd =
      open_socket (_options.ipv6 () ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    errno_assert (sd != -1);

    struct ifreq ifr;

    //  Copy interface name for ioctl get.
    strncpy (ifr.ifr_name, nic_, sizeof (ifr.ifr_name));

    //  Fetch interface address.
    const int rc = ioctl (sd, SIOCGIFADDR, (caddr_t) &ifr, sizeof (ifr));

    //  Clean up.
    close (sd);

    if (rc == -1) {
        errno = ENODEV;
        return -1;
    }

    const int family = ifr.ifr_addr.sa_family;
    if (family == (_options.ipv6 () ? AF_INET6 : AF_INET)
        && !strcmp (nic_, ifr.ifr_name)) {
        memcpy (ip_addr_, &ifr.ifr_addr,
                (family == AF_INET) ? sizeof (struct sockaddr_in)
                                    : sizeof (struct sockaddr_in6));
    } else {
        errno = ENODEV;
        return -1;
    }

    return 0;
}

#elif ((defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD                     \
        || defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_OPENBSD                    \
        || defined ZMQ_HAVE_QNXNTO || defined ZMQ_HAVE_NETBSD                  \
        || defined ZMQ_HAVE_DRAGONFLY || defined ZMQ_HAVE_GNU)                 \
       && defined ZMQ_HAVE_IFADDRS)

#include <ifaddrs.h>

//  On these platforms, network interface name can be queried
//  using getifaddrs function.
int zmq::ip_resolver_t::resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_)
{
    //  Get the addresses.
    ifaddrs *ifa = NULL;
    int rc = 0;
    const int max_attempts = 10;
    const int backoff_msec = 1;
    for (int i = 0; i < max_attempts; i++) {
        rc = getifaddrs (&ifa);
        if (rc == 0 || (rc < 0 && errno != ECONNREFUSED))
            break;
        usleep ((backoff_msec << i) * 1000);
    }

    if (rc != 0 && ((errno == EINVAL) || (errno == EOPNOTSUPP))) {
        // Windows Subsystem for Linux compatibility
        errno = ENODEV;
        return -1;
    }
    errno_assert (rc == 0);
    zmq_assert (ifa != NULL);

    //  Find the corresponding network interface.
    bool found = false;
    for (ifaddrs *ifp = ifa; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL)
            continue;

        const int family = ifp->ifa_addr->sa_family;
        if (family == (_options.ipv6 () ? AF_INET6 : AF_INET)
            && !strcmp (nic_, ifp->ifa_name)) {
            memcpy (ip_addr_, ifp->ifa_addr,
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

#elif (defined ZMQ_HAVE_WINDOWS)

#include <netioapi.h>

int zmq::ip_resolver_t::get_interface_name (unsigned long index_,
                                            char **dest_) const
{
#ifdef ZMQ_HAVE_WINDOWS_UWP
    char *buffer = (char *) malloc (1024);
#else
    char *buffer = static_cast<char *> (malloc (IF_MAX_STRING_SIZE));
#endif
    alloc_assert (buffer);

    char *if_name_result = NULL;

#if !defined ZMQ_HAVE_WINDOWS_TARGET_XP && !defined ZMQ_HAVE_WINDOWS_UWP
    if_name_result = if_indextoname (index_, buffer);
#endif

    if (if_name_result == NULL) {
        free (buffer);
        return -1;
    }

    *dest_ = buffer;
    return 0;
}

int zmq::ip_resolver_t::wchar_to_utf8 (const WCHAR *src_, char **dest_) const
{
    int rc;
    int buffer_len =
      WideCharToMultiByte (CP_UTF8, 0, src_, -1, NULL, 0, NULL, 0);

    char *buffer = static_cast<char *> (malloc (buffer_len));
    alloc_assert (buffer);

    rc =
      WideCharToMultiByte (CP_UTF8, 0, src_, -1, buffer, buffer_len, NULL, 0);

    if (rc == 0) {
        free (buffer);
        return -1;
    }

    *dest_ = buffer;
    return 0;
}

int zmq::ip_resolver_t::resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_)
{
    int rc;
    bool found = false;
    const int max_attempts = 10;

    int iterations = 0;
    IP_ADAPTER_ADDRESSES *addresses;
    unsigned long out_buf_len = sizeof (IP_ADAPTER_ADDRESSES);

    do {
        addresses = static_cast<IP_ADAPTER_ADDRESSES *> (malloc (out_buf_len));
        alloc_assert (addresses);

        rc =
          GetAdaptersAddresses (AF_UNSPEC,
                                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST
                                  | GAA_FLAG_SKIP_DNS_SERVER,
                                NULL, addresses, &out_buf_len);
        if (rc == ERROR_BUFFER_OVERFLOW) {
            free (addresses);
            addresses = NULL;
        } else {
            break;
        }
        iterations++;
    } while ((rc == ERROR_BUFFER_OVERFLOW) && (iterations < max_attempts));

    if (rc == 0) {
        for (const IP_ADAPTER_ADDRESSES *current_addresses = addresses;
             current_addresses; current_addresses = current_addresses->Next) {
            char *if_name = NULL;
            char *if_friendly_name = NULL;

            const int str_rc1 =
              get_interface_name (current_addresses->IfIndex, &if_name);
            const int str_rc2 = wchar_to_utf8 (current_addresses->FriendlyName,
                                               &if_friendly_name);

            //  Find a network adapter by its "name" or "friendly name"
            if (((str_rc1 == 0) && (!strcmp (nic_, if_name)))
                || ((str_rc2 == 0) && (!strcmp (nic_, if_friendly_name)))) {
                //  Iterate over all unicast addresses bound to the current network interface
                for (const IP_ADAPTER_UNICAST_ADDRESS *current_unicast_address =
                       current_addresses->FirstUnicastAddress;
                     current_unicast_address;
                     current_unicast_address = current_unicast_address->Next) {
                    const ADDRESS_FAMILY family =
                      current_unicast_address->Address.lpSockaddr->sa_family;

                    if (family == (_options.ipv6 () ? AF_INET6 : AF_INET)) {
                        memcpy (
                          ip_addr_, current_unicast_address->Address.lpSockaddr,
                          (family == AF_INET) ? sizeof (struct sockaddr_in)
                                              : sizeof (struct sockaddr_in6));
                        found = true;
                        break;
                    }
                }

                if (found)
                    break;
            }

            if (str_rc1 == 0)
                free (if_name);
            if (str_rc2 == 0)
                free (if_friendly_name);
        }

        free (addresses);
    }

    if (!found) {
        errno = ENODEV;
        return -1;
    }
    return 0;
}

#else

//  On other platforms we assume there are no sane interface names.
int zmq::ip_resolver_t::resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_)
{
    LIBZMQ_UNUSED (ip_addr_);
    LIBZMQ_UNUSED (nic_);

    errno = ENODEV;
    return -1;
}

#endif

int zmq::ip_resolver_t::do_getaddrinfo (const char *node_,
                                        const char *service_,
                                        const struct addrinfo *hints_,
                                        struct addrinfo **res_)
{
    return getaddrinfo (node_, service_, hints_, res_);
}

void zmq::ip_resolver_t::do_freeaddrinfo (struct addrinfo *res_)
{
    freeaddrinfo (res_);
}

unsigned int zmq::ip_resolver_t::do_if_nametoindex (const char *ifname_)
{
#if !defined ZMQ_HAVE_WINDOWS_TARGET_XP && !defined ZMQ_HAVE_WINDOWS_UWP       \
  && !defined ZMQ_HAVE_VXWORKS
    return if_nametoindex (ifname_);
#else
    // The function 'if_nametoindex' is not supported on Windows XP.
    // If we are targeting XP using a vxxx_xp toolset then fail.
    // This is brutal as this code could be run on later windows clients
    // meaning the IPv6 zone_id cannot have an interface name.
    // This could be fixed with a runtime check.
    return 0;
#endif
}
