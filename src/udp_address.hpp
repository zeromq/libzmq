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

#ifndef __ZMQ_UDP_ADDRESS_HPP_INCLUDED__
#define __ZMQ_UDP_ADDRESS_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <string>

#include "ip_resolver.hpp"

namespace zmq
{
class udp_address_t
{
  public:
    udp_address_t ();
    virtual ~udp_address_t ();

    int resolve (const char *name_, bool bind_, bool ipv6_);

    //  The opposite to resolve()
    virtual int to_string (std::string &addr_);


    int family () const;

    bool is_mcast () const;

    const ip_addr_t *bind_addr () const;
    int bind_if () const;
    const ip_addr_t *target_addr () const;

  private:
    ip_addr_t _bind_address;
    int _bind_interface;
    ip_addr_t _target_address;
    bool _is_multicast;
    std::string _address;
};
}

#endif
