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

#ifndef __ZMQ_IP_HPP_INCLUDED__
#define __ZMQ_IP_HPP_INCLUDED__

#include <string>
#include "fd.hpp"

namespace zmq
{

    //  Same as socket(2), but allows for transparent tweaking the options.
    fd_t open_socket (int domain_, int type_, int protocol_);

    //  Sets the socket into non-blocking mode.
    void unblock_socket (fd_t s_);

    //  Enable IPv4-mapping of addresses in case it is disabled by default.
    void enable_ipv4_mapping (fd_t s_);

    //  Returns string representation of peer's address.
    //  Socket sockfd_ must be connected. Returns true iff successful.
    int get_peer_ip_address (fd_t sockfd_, std::string &ip_addr_);

    // Sets the IP Type-Of-Service for the underlying socket
    void set_ip_type_of_service (fd_t s_, int iptos);

}

#endif
