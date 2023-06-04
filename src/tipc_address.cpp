/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include "tipc_address.hpp"

#if defined ZMQ_HAVE_TIPC

#include "err.hpp"

#include <string>
#include <sstream>

zmq::tipc_address_t::tipc_address_t ()
{
    memset (&address, 0, sizeof address);
    _random = false;
}

zmq::tipc_address_t::tipc_address_t (const sockaddr *sa_, socklen_t sa_len_)
{
    zmq_assert (sa_ && sa_len_ > 0);

    memset (&address, 0, sizeof address);
    if (sa_->sa_family == AF_TIPC)
        memcpy (&address, sa_, sa_len_);

    _random = false;
}

void zmq::tipc_address_t::set_random ()
{
    _random = true;
}
bool zmq::tipc_address_t::is_random () const
{
    return _random;
}
bool zmq::tipc_address_t::is_service () const
{
    if (address.addrtype == TIPC_ADDR_ID)
        return false;

    return true;
}
int zmq::tipc_address_t::resolve (const char *name_)
{
    unsigned int type = 0;
    unsigned int lower = 0;
    unsigned int upper = 0;
    unsigned int ref = 0;
    unsigned int z = 1, c = 0, n = 0;
    char eof;
    const char *domain;
    int res;


    if (strncmp (name_, "<*>", 3) == 0) {
        set_random ();
        address.family = AF_TIPC;
        address.addrtype = TIPC_ADDR_ID;
        address.addr.id.node = 0;
        address.addr.id.ref = 0;
        address.scope = 0;
        return 0;
    }

    res = sscanf (name_, "{%u,%u,%u}", &type, &lower, &upper);
    /* Fetch optional domain suffix. */
    if ((domain = strchr (name_, '@'))) {
        if (sscanf (domain, "@%u.%u.%u%c", &z, &c, &n, &eof) != 3)
            return EINVAL;
    }
    if (res == 3) {
        if (type < TIPC_RESERVED_TYPES || upper < lower)
            return EINVAL;
        address.family = AF_TIPC;
        address.addrtype = TIPC_ADDR_NAMESEQ;
        address.addr.nameseq.type = type;
        address.addr.nameseq.lower = lower;
        address.addr.nameseq.upper = upper;
        address.scope = TIPC_ZONE_SCOPE;
        return 0;
    }
    if (res == 2 && type > TIPC_RESERVED_TYPES) {
        address.family = AF_TIPC;
        address.addrtype = TIPC_ADDR_NAME;
        address.addr.name.name.type = type;
        address.addr.name.name.instance = lower;
        address.addr.name.domain = tipc_addr (z, c, n);
        address.scope = 0;
        return 0;
    } else if (res == 0) {
        res = sscanf (name_, "<%u.%u.%u:%u>", &z, &c, &n, &ref);
        if (res == 4) {
            address.family = AF_TIPC;
            address.addrtype = TIPC_ADDR_ID;
            address.addr.id.node = tipc_addr (z, c, n);
            address.addr.id.ref = ref;
            address.scope = 0;
            return 0;
        }
    }
    return EINVAL;
}

int zmq::tipc_address_t::to_string (std::string &addr_) const
{
    if (address.family != AF_TIPC) {
        addr_.clear ();
        return -1;
    }
    std::stringstream s;
    if (address.addrtype == TIPC_ADDR_NAMESEQ
        || address.addrtype == TIPC_ADDR_NAME) {
        s << "tipc://"
          << "{" << address.addr.nameseq.type;
        s << ", " << address.addr.nameseq.lower;
        s << ", " << address.addr.nameseq.upper << "}";
        addr_ = s.str ();
    } else if (address.addrtype == TIPC_ADDR_ID || is_random ()) {
        s << "tipc://"
          << "<" << tipc_zone (address.addr.id.node);
        s << "." << tipc_cluster (address.addr.id.node);
        s << "." << tipc_node (address.addr.id.node);
        s << ":" << address.addr.id.ref << ">";
        addr_ = s.str ();
    } else {
        addr_.clear ();
        return -1;
    }
    return 0;
}

const sockaddr *zmq::tipc_address_t::addr () const
{
    return (sockaddr *) &address;
}

socklen_t zmq::tipc_address_t::addrlen () const
{
    return static_cast<socklen_t> (sizeof address);
}

#endif
