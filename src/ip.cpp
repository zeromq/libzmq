/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "ip.hpp"
#include "platform.hpp"
#include "err.hpp"
#include "stdint.hpp"

#if defined ZMQ_HAVE_SOLARIS

#include <sys/sockio.h>
#include <net/if.h>
#include <unistd.h>

//  On Solaris platform, network interface name can be queried by ioctl.
static int resolve_nic_name (in_addr* addr_, char const *interface_)
{
    //  Create a socket.
    int fd = socket (AF_INET, SOCK_DGRAM, 0);
    zmq_assert (fd != -1);

    //  Retrieve number of interfaces.
    lifnum ifn;
    ifn.lifn_family = AF_UNSPEC;
    ifn.lifn_flags = 0;
    int rc = ioctl (fd, SIOCGLIFNUM, (char*) &ifn);
    zmq_assert (rc != -1);

    //  Allocate memory to get interface names.
    size_t ifr_size = sizeof (struct lifreq) * ifn.lifn_count;
    char *ifr = (char*) malloc (ifr_size);
    errno_assert (ifr);
    
    //  Retrieve interface names.
    lifconf ifc;
    ifc.lifc_family = AF_UNSPEC;
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
        if (!strcmp (interface_, ifrp->lifr_name)) {
            rc = ioctl (fd, SIOCGLIFADDR, (char*) ifrp);
            zmq_assert (rc != -1);
            if (ifrp->lifr_addr.ss_family == AF_INET) {
                *addr_ = ((sockaddr_in*) &ifrp->lifr_addr)->sin_addr;
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

#elif defined ZMQ_HAVE_AIX || ZMQ_HAVE_HPUX

#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "formatting.hpp"

static int resolve_nic_name (in_addr* addr_, char const *interface_)
{
    //  Create a socket.
    int sd = socket (AF_INET, SOCK_DGRAM, 0);
    zmq_assert (sd != -1);

    struct ifreq ifr; 

    //  Copy interface name for ioctl get.
    zmq_strncpy (ifr.ifr_name, interface_, sizeof (ifr.ifr_name));

    //  Fetch interface address.
    int rc = ioctl (sd, SIOCGIFADDR, (caddr_t) &ifr, sizeof (struct ifreq));

    //  Clean up.
    close (sd);

    if (rc == -1) {
        errno = ENODEV;
        return -1;
    }

    struct sockaddr *sa = (struct sockaddr *) &ifr.ifr_addr;
    *addr_ = ((sockaddr_in*)sa)->sin_addr;
    return 0;    
}

#elif ((defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_OPENBSD ||\
    defined ZMQ_HAVE_QNXNTO) && defined ZMQ_HAVE_IFADDRS)

#include <ifaddrs.h>

//  On these platforms, network interface name can be queried
//  using getifaddrs function.
static int resolve_nic_name (in_addr* addr_, char const *interface_)
{
    //  Get the addresses.
    ifaddrs* ifa = NULL;
    int rc = getifaddrs (&ifa);
    zmq_assert (rc == 0);    
    zmq_assert (ifa != NULL);

    //  Find the corresponding network interface.
    bool found = false;
    for (ifaddrs *ifp = ifa; ifp != NULL ;ifp = ifp->ifa_next)
        if (ifp->ifa_addr && ifp->ifa_addr->sa_family == AF_INET 
            && !strcmp (interface_, ifp->ifa_name)) 
        {
            *addr_ = ((sockaddr_in*) ifp->ifa_addr)->sin_addr;
            found = true;
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
static int resolve_nic_name (in_addr* addr_, char const *interface_)
{
    errno = ENODEV;
    return -1;
}

#endif

int zmq::resolve_ip_interface (sockaddr_storage* addr_, char const *interface_)
{
    //  Find the end ':' that separates NIC name from service.
    const char *delimiter = strrchr (interface_, ':');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //  Separate the name/port
    std::string interface (interface_, delimiter - interface_);
    std::string service (delimiter + 1);

    //  Initialize the output parameter.
    memset (addr_, 0, sizeof (*addr_));

    //  Initialise IPv4-format family/port.
    sockaddr_in ip4_addr;
    ip4_addr.sin_family = AF_INET;
    ip4_addr.sin_port = htons ((uint16_t) atoi (service.c_str()));

    //  Initialize temporary output pointers with ip4_addr
    sockaddr *out_addr = (sockaddr *) &ip4_addr;
    size_t out_addrlen = sizeof (ip4_addr);

    //  0 is not a valid port.
    if (!ip4_addr.sin_port) {
        errno = EINVAL;
        return -1;
    }

    //  * resolves to INADDR_ANY.
    if (interface.compare("*") == 0) {
        ip4_addr.sin_addr.s_addr = htonl (INADDR_ANY);
        zmq_assert (out_addrlen <= sizeof (*addr_));
        memcpy (addr_, out_addr, out_addrlen);
        return 0;
    }

    //  Try to resolve the string as a NIC name.
    int rc = resolve_nic_name (&ip4_addr.sin_addr, interface.c_str());
    if (rc != 0 && errno != ENODEV)
        return rc;
    if (rc == 0) {
        zmq_assert (out_addrlen <= sizeof (*addr_));
        memcpy (addr_, out_addr, out_addrlen);
        return 0;
    }

    //  There's no such interface name. Assume literal address.
    rc = inet_pton (AF_INET, interface.c_str(), &ip4_addr.sin_addr);
    if (rc == 0) {
        errno = ENODEV;
        return -1;
    }
    if (rc < 0)
        return -1;

    zmq_assert (out_addrlen <= sizeof (*addr_));
    memcpy (addr_, out_addr, out_addrlen);
    return 0;
}

int zmq::resolve_ip_hostname (sockaddr_storage *addr_, const char *hostname_)
{
    sockaddr_in *addr = (sockaddr_in*) addr_;

    //  Find the ':' that separates hostname name from port.
    const char *delimiter = strchr (hostname_, ':');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //  Separate the hostname.
    std::string hostname (hostname_, delimiter - hostname_);

    //  Resolve host name. Some of the error info is lost in case of error,
    //  however, there's no way to report EAI errors via errno.
    addrinfo req;
    memset (&req, 0, sizeof (req));
    req.ai_family = AF_INET;
    addrinfo *res;
    int rc = getaddrinfo (hostname.c_str (), NULL, &req, &res);
    if (rc) {
        errno = EINVAL;
        return -1;
    }
    zmq_assert (res->ai_addr->sa_family == AF_INET);
    memcpy (addr, res->ai_addr, sizeof (sockaddr_in));
    freeaddrinfo (res);
    
    //  Fill in the port number.
    addr->sin_port = htons ((uint16_t) atoi (delimiter + 1));
    if (!addr->sin_port) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

int zmq::resolve_local_path (sockaddr_un *addr_, const char *path_)
{
    if (strlen (path_) >= sizeof (addr_->sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy (addr_->sun_path, path_);
    addr_->sun_family = AF_UNIX;
    return 0;
}

#endif

