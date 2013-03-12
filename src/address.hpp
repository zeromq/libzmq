/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_ADDRESS_HPP_INCLUDED__
#define __ZMQ_ADDRESS_HPP_INCLUDED__

#include <string>

namespace zmq
{
    class tcp_address_t;
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    class ipc_address_t;
#endif
    struct address_t {
        address_t (const std::string &protocol_, const std::string &address_);

        ~address_t ();

        const std::string protocol;
        const std::string address;

        //  Protocol specific resolved address
        union {
            tcp_address_t *tcp_addr;
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
            ipc_address_t *ipc_addr;
#endif
        } resolved;

        int to_string (std::string &addr_) const;
    };
}

#endif
