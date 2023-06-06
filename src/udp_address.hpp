/* SPDX-License-Identifier: MPL-2.0 */

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
