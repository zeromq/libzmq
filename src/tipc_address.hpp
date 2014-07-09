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

#ifndef __ZMQ_TIPC_ADDRESS_HPP_INCLUDED__
#define __ZMQ_TIPC_ADDRESS_HPP_INCLUDED__

#include <string>

#include "platform.hpp"

#if defined ZMQ_HAVE_TIPC

#include <sys/socket.h>
#include <linux/tipc.h>

namespace zmq
{

    class tipc_address_t
    {
    public:

        tipc_address_t ();
        tipc_address_t (const sockaddr *sa, socklen_t sa_len);
        ~tipc_address_t ();

        //  This function sets up the address "{type, lower, upper}" for TIPC transport
        int resolve (const char *name);

        //  The opposite to resolve()
        int to_string (std::string &addr_);

        const sockaddr *addr () const;
        socklen_t addrlen () const;

    private:

        struct sockaddr_tipc address;

        tipc_address_t (const tipc_address_t&);
        const tipc_address_t &operator = (const tipc_address_t&);
    };

}

#endif

#endif

