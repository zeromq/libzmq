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

#ifndef __ZMQ_IPC_ADDRESS_HPP_INCLUDED__
#define __ZMQ_IPC_ADDRESS_HPP_INCLUDED__

#include <string>

#include "platform.hpp"

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS

#include <sys/socket.h>
#include <sys/un.h>

namespace zmq
{

    class ipc_address_t
    {
    public:

        ipc_address_t ();
        ipc_address_t (const sockaddr *sa, socklen_t sa_len);
        ~ipc_address_t ();

        //  This function sets up the address for UNIX domain transport.
        int resolve (const char *path_);

        //  The opposite to resolve()
        int to_string (std::string &addr_);

        const sockaddr *addr () const;
        socklen_t addrlen () const;

    private:

        struct sockaddr_un address;

        ipc_address_t (const ipc_address_t&);
        const ipc_address_t &operator = (const ipc_address_t&);
    };

}

#endif

#endif


