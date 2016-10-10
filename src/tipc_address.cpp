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

#include "tipc_address.hpp"

#if defined ZMQ_HAVE_TIPC

#include "err.hpp"

#include <string>
#include <sstream>

zmq::tipc_address_t::tipc_address_t ()
{
    memset (&address, 0, sizeof address);
}

zmq::tipc_address_t::tipc_address_t (const sockaddr *sa, socklen_t sa_len)
{
    zmq_assert (sa && sa_len > 0);

    memset (&address, 0, sizeof address);
    if (sa->sa_family == AF_TIPC)
        memcpy (&address, sa, sa_len);
}

zmq::tipc_address_t::~tipc_address_t ()
{
}

int zmq::tipc_address_t::resolve (const char *name)
{
    unsigned int type = 0;
    unsigned int lower = 0;
    unsigned int upper = 0;
    unsigned int z = 1, c = 0, n = 0;
    char eof;
    const char *domain;
    const int res = sscanf (name, "{%u,%u,%u}", &type, &lower, &upper);

    /* Fetch optional domain suffix. */
    if ((domain = strchr(name, '@'))) {
        if (sscanf(domain, "@%u.%u.%u%c", &z, &c, &n, &eof) != 3)
            return EINVAL;
    }
    if (res == 3)
        goto nameseq;
    else
    if (res == 2 && type > TIPC_RESERVED_TYPES) {
        address.family = AF_TIPC;
        address.addrtype = TIPC_ADDR_NAME;
        address.addr.name.name.type = type;
        address.addr.name.name.instance = lower;
        address.addr.name.domain = tipc_addr (z, c, n);
        address.scope = 0;
        return 0;
    }
    else
        return EINVAL;
nameseq:
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

int zmq::tipc_address_t::to_string (std::string &addr_)
{
    if (address.family != AF_TIPC) {
        addr_.clear ();
        return -1;
    }
    std::stringstream s;
    s << "tipc://" << "{" << address.addr.nameseq.type;
    s << ", " << address.addr.nameseq.lower;
    s << ", " << address.addr.nameseq.upper << "}";
    addr_ = s.str ();
    return 0;
}

const sockaddr *zmq::tipc_address_t::addr () const
{
    return (sockaddr*) &address;
}

socklen_t zmq::tipc_address_t::addrlen () const
{
    return (socklen_t) sizeof address;
}

#endif
