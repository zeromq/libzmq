/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "hvsocket_address.hpp"

#if defined(ZMQ_HAVE_HVSOCKET)

//
// Windows Registry Editor Version 5.00
//
// [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]
// "ElementName"="Your Channel Name"
//

#include <climits>
#include <string>
#include <sstream>
#include <iomanip>

#include "err.hpp"

zmq::hvsocket_address_t::hvsocket_address_t ()
{
    memset (&address, 0, sizeof address);
}

zmq::hvsocket_address_t::hvsocket_address_t (ctx_t *parent_) : parent (parent_)
{
    memset (&address, 0, sizeof address);
}

zmq::hvsocket_address_t::hvsocket_address_t (const sockaddr *sa,
                                             socklen_t sa_len,
                                             ctx_t *parent_) :
    parent (parent_)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof (address));

    if (sa->sa_family == parent->get_hvsocket_socket_family ()) {
        zmq_assert (sa_len <= sizeof (address));
        memcpy (&address, sa, sa_len);
    }
}

const bool GuidFromString (const char *str, GUID *guid)
{
    //
    // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    //

    const size_t len = strlen (str);

    if (len != 36) {
        return false;
    }

    //
    // Validate the string format
    //

    for (int i = 0; i < len; ++i) {
        const char g = str[i];
        if ((i == 8) || (i == 13) || (i == 18) || (i == 23)) {
            if (g != '-') {
                return false;
            }
        } else if (!std::isxdigit (g)) {
            return false;
        }
    }

    char *pEnd;

    guid->Data1 = strtoul (str, &pEnd, 16);
    guid->Data2 = (unsigned short) strtoul (str + 9, &pEnd, 16);
    guid->Data3 = (unsigned short) strtoul (str + 14, &pEnd, 16);

    char b[3]{};

    b[0] = str[19];
    b[1] = str[20];

    guid->Data4[0] = (unsigned char) strtoul (b, &pEnd, 16);

    b[0] = str[21];
    b[1] = str[22];

    guid->Data4[1] = (unsigned char) strtoul (b, &pEnd, 16);

    for (int i = 0; i < 6; ++i) {
        memcpy (b, str + 24 + i * 2, 2 * sizeof (b[0]));
        guid->Data4[2 + i] = (unsigned char) strtoul (b, &pEnd, 16);
    }

    return true;
}

std::ostream &operator<< (std::ostream &os, REFGUID guid)
{
    os << std::uppercase;

    os << std::hex << std::setfill ('0') << std::setw (8)
       << guid.Data1 << '-';

    os << std::hex << std::setfill ('0') << std::setw (4)
       << guid.Data2 << '-';

    os << std::hex << std::setfill ('0') << std::setw (4)
       << guid.Data3 << '-';

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[0]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[1]) << '-';

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[2]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[3]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[4]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[5]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[6]);

    os << std::hex << std::setfill ('0') << std::setw (2)
       << static_cast<short> (guid.Data4[7]);

    os << std::nouppercase;

    return os;
}

int zmq::hvsocket_address_t::resolve (const char *path_)
{
#ifndef NDEBUG
    // TODO: Mode this into a test
    GUID guid{};
    zmq_assert (
      GuidFromString ("C0B6B7FC-0D90-4812-A606-9E8E13709825", &guid));
    std::stringstream s; s << guid;
    zmq_assert (s.str () == "C0B6B7FC-0D90-4812-A606-9E8E13709825");
#endif

    //    if (!GuidFromString (path_, &guid)) {
    //        errno = EINVAL;
    //        return -1;
    //    }

    //
    //  Find the ':' at end that separates the VM ID from the Service ID.
    //

    const char *delimiter = strrchr (path_, ':');

    if (!delimiter) {
        errno = EINVAL;
        return -1;
    }

    //
    //  Separate the VM ID / Service ID.
    //

    std::string addr_str (path_, delimiter - path_);
    std::string port_str (delimiter + 1);

    address.VmId = HV_GUID_WILDCARD;
    address.ServiceId = HV_GUID_WILDCARD;

    if (!addr_str.length ()) {
        errno = EINVAL;
        return -1;
    } else if (addr_str != "*") {
        if (!GuidFromString (addr_str.c_str (), &address.VmId)) {
            errno = EINVAL;
            return -1;
        }
    }

    if (!port_str.length ()) {
        errno = EINVAL;
        return -1;
    } else if (port_str != "*") {
        if (!GuidFromString (port_str.c_str (), &address.ServiceId)) {
            errno = EINVAL;
            return -1;
        }
    }

    address.Family =
      static_cast<unsigned short> (parent->get_hvsocket_socket_family ());

    return 0;
}

int zmq::hvsocket_address_t::to_string (std::string &addr_) const
{
    if (address.Family != parent->get_hvsocket_socket_family ()) {
        addr_.clear ();
        return -1;
    }

    std::stringstream s;
    s << protocol_name::hvsocket << "://";
    s << address.VmId;
    s << ":";
    s << address.ServiceId;
    addr_ = s.str ();

    return 0;
}

const sockaddr *zmq::hvsocket_address_t::addr () const
{
    return reinterpret_cast<const sockaddr *> (&address);
}

socklen_t zmq::hvsocket_address_t::addrlen () const
{
    return static_cast<socklen_t> (sizeof address);
}

#if defined ZMQ_HAVE_WINDOWS
unsigned short zmq::hvsocket_address_t::family () const
#else
sa_family_t zmq::hvsocket_address_t::family () const
#endif
{
    return AF_HYPERV;
}

#endif
