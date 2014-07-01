/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

    const int res = sscanf (name, "{%u,%u,%u}", &type, &lower, &upper);
    if (res == 3)
        goto nameseq;
    else
    if (res == 2 && type > TIPC_RESERVED_TYPES) {
        address.family = AF_TIPC;
        address.addrtype = TIPC_ADDR_NAME;
        address.addr.name.name.type = type;
        address.addr.name.name.instance = lower;
        /* Since we can't specify lookup domain when connecting
         * (and we're not sure that we want it to be configurable)
         * Change from 'closest first' approach, to search entire zone */
        address.addr.name.domain = tipc_addr (1, 0, 0);
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
