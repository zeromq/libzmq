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

#include "vmci_address.hpp"

#if defined(ZMQ_HAVE_VMCI)

#include <climits>
#include <string>
#include <sstream>

#include "err.hpp"

zmq::vmci_address_t::vmci_address_t(ctx_t *parent_) :
    parent(parent_)
{
    memset (&address, 0, sizeof address);
}

zmq::vmci_address_t::vmci_address_t(const sockaddr *sa, socklen_t sa_len, ctx_t *parent_) :
    parent(parent_)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof address);
    if (sa->sa_family == parent->get_vmci_socket_family())
        memcpy(&address, sa, sa_len);
}

zmq::vmci_address_t::~vmci_address_t ()
{
}

int zmq::vmci_address_t::resolve(const char *path_)
{
    //  Find the ':' at end that separates address from the port number.
    const char *delimiter = strrchr (path_, ':');
    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //  Separate the address/port.
    std::string addr_str (path_, delimiter - path_);
    std::string port_str (delimiter + 1);

    unsigned int cid = VMADDR_CID_ANY;
    unsigned int port = VMADDR_PORT_ANY;

    if (!addr_str.length()) {
        errno = EINVAL;
        return -1;
    }
    else if (addr_str == "@") {
        cid = VMCISock_GetLocalCID();

        if (cid == VMADDR_CID_ANY) {
            errno = ENODEV;
            return -1;
        }
    }
    else if (addr_str != "*" && addr_str != "-1") {
        const char *begin = addr_str.c_str();
        char *end = NULL;
        unsigned long l = strtoul(begin, &end, 10);

        if ((l == 0 && end == begin) || (l == ULONG_MAX && errno == ERANGE) || l > UINT_MAX)
        {
            errno = EINVAL;
            return -1;
        }

        cid = static_cast<unsigned int> (l);
    }

    if (!port_str.length()) {
        errno = EINVAL;
        return -1;
    }
    else if (port_str != "*" && port_str != "-1") {
        const char *begin = port_str.c_str();
        char *end = NULL;
        unsigned long l = strtoul(begin, &end, 10);

        if ((l == 0 && end == begin) || (l == ULONG_MAX && errno == ERANGE) || l > UINT_MAX) {
            errno = EINVAL;
            return -1;
        }

        port = static_cast<unsigned int> (l);
    }

    address.svm_family = static_cast<sa_family_t> (parent->get_vmci_socket_family());
    address.svm_cid = cid;
    address.svm_port = port;

    return 0;
}

int zmq::vmci_address_t::to_string (std::string &addr_)
{
    if (address.svm_family != parent->get_vmci_socket_family()) {
        addr_.clear ();
        return -1;
    }

    std::stringstream s;

    s << "vmci://";

    if (address.svm_cid == VMADDR_CID_ANY) {
        s << "*";
    }
    else
    {
        s << address.svm_cid;
    }

    s << ":";

    if (address.svm_port == VMADDR_PORT_ANY) {
        s << "*";
    }
    else {
        s << address.svm_port;
    }

    addr_ = s.str ();
    return 0;
}

const sockaddr *zmq::vmci_address_t::addr () const
{
    return reinterpret_cast<const sockaddr*> (&address);
}

socklen_t zmq::vmci_address_t::addrlen () const
{
    return static_cast<socklen_t> (sizeof address);
}

#endif
