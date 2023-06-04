/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "vmci_address.hpp"

#if defined(ZMQ_HAVE_VMCI)

#include <climits>
#include <string>
#include <sstream>

#include "err.hpp"

zmq::vmci_address_t::vmci_address_t ()
{
    memset (&address, 0, sizeof address);
}

zmq::vmci_address_t::vmci_address_t (ctx_t *parent_) : parent (parent_)
{
    memset (&address, 0, sizeof address);
}

zmq::vmci_address_t::vmci_address_t (const sockaddr *sa,
                                     socklen_t sa_len,
                                     ctx_t *parent_) :
    parent (parent_)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof address);
    if (sa->sa_family == parent->get_vmci_socket_family ())
        memcpy (&address, sa, sa_len);
}

int zmq::vmci_address_t::resolve (const char *path_)
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

    if (!addr_str.length ()) {
        errno = EINVAL;
        return -1;
    } else if (addr_str == "@") {
        cid = VMCISock_GetLocalCID ();

        if (cid == VMADDR_CID_ANY) {
            errno = ENODEV;
            return -1;
        }
    } else if (addr_str != "*" && addr_str != "-1") {
        const char *begin = addr_str.c_str ();
        char *end = NULL;
        unsigned long l = strtoul (begin, &end, 10);

        if ((l == 0 && end == begin) || (l == ULONG_MAX && errno == ERANGE)
            || l > UINT_MAX) {
            errno = EINVAL;
            return -1;
        }

        cid = static_cast<unsigned int> (l);
    }

    if (!port_str.length ()) {
        errno = EINVAL;
        return -1;
    } else if (port_str != "*" && port_str != "-1") {
        const char *begin = port_str.c_str ();
        char *end = NULL;
        unsigned long l = strtoul (begin, &end, 10);

        if ((l == 0 && end == begin) || (l == ULONG_MAX && errno == ERANGE)
            || l > UINT_MAX) {
            errno = EINVAL;
            return -1;
        }

        port = static_cast<unsigned int> (l);
    }

    address.svm_family =
      static_cast<sa_family_t> (parent->get_vmci_socket_family ());
    address.svm_cid = cid;
    address.svm_port = port;

    return 0;
}

int zmq::vmci_address_t::to_string (std::string &addr_) const
{
    if (address.svm_family != parent->get_vmci_socket_family ()) {
        addr_.clear ();
        return -1;
    }

    std::stringstream s;

    s << "vmci://";

    if (address.svm_cid == VMADDR_CID_ANY) {
        s << "*";
    } else {
        s << address.svm_cid;
    }

    s << ":";

    if (address.svm_port == VMADDR_PORT_ANY) {
        s << "*";
    } else {
        s << address.svm_port;
    }

    addr_ = s.str ();
    return 0;
}

const sockaddr *zmq::vmci_address_t::addr () const
{
    return reinterpret_cast<const sockaddr *> (&address);
}

socklen_t zmq::vmci_address_t::addrlen () const
{
    return static_cast<socklen_t> (sizeof address);
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::vmci_address_t::family () const
#else
sa_family_t zmq::vmci_address_t::family () const
#endif
{
    return parent->get_vmci_socket_family ();
}

#endif
