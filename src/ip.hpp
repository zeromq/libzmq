/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include "fd.hpp"

namespace zmq
{

    //  Same as socket(2), but allows for transparent tweaking the options.
    fd_t open_socket (int domain_, int type_, int protocol_);

    //  Tunes the supplied TCP socket for the best latency.
    void tune_tcp_socket (fd_t s_);

    //  Sets the socket into non-blocking mode.
    void unblock_socket (fd_t s_);

    //  Enable IPv4-mapping of addresses in case it is disabled by default.
    void enable_ipv4_mapping (fd_t s_);

}

#endif 
