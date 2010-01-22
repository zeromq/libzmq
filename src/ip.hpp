/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_IP_HPP_INCLUDED__
#define __ZMQ_IP_HPP_INCLUDED__

#include "platform.hpp"

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
#include <sys/un.h>
#endif

namespace zmq
{

    //  Resolves network interface name in <nic-name>:<port> format. Symbol "*"
    //  (asterisk) resolves to INADDR_ANY (all network interfaces).
    int resolve_ip_interface (sockaddr_storage *addr_, char const *interface_);

    //  This function resolves a string in <hostname>:<port-number> format.
    //  Hostname can be either the name of the host or its IP address.
    int resolve_ip_hostname (sockaddr_storage *addr_, const char *hostname_);

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    // This function sets up the sockaddr_un structure with the pathname_
    int resolve_local_path (sockaddr_un *addr_, const char* pathname_);
#endif
}

#endif 
