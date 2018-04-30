/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_IP_RESOLVER_HPP_INCLUDED__
#define __ZMQ_IP_RESOLVER_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace zmq
{
union ip_addr_t
{
    sockaddr generic;
    sockaddr_in ipv4;
    sockaddr_in6 ipv6;
};

class ip_resolver_options_t
{
  public:
    ip_resolver_options_t ();

    ip_resolver_options_t &bindable (bool bindable_);
    ip_resolver_options_t &allow_nic_name (bool allow_);
    ip_resolver_options_t &ipv6 (bool ipv6_);
    ip_resolver_options_t &expect_port (bool expect_);
    ip_resolver_options_t &allow_dns (bool allow_);

    bool bindable ();
    bool allow_nic_name ();
    bool ipv6 ();
    bool expect_port ();
    bool allow_dns ();

  private:
    bool bindable_wanted;
    bool nic_name_allowed;
    bool ipv6_wanted;
    bool port_expected;
    bool dns_allowed;
};

class ip_resolver_t
{
  public:
    ip_resolver_t (ip_resolver_options_t opts_);

    int resolve (ip_addr_t *ip_addr_, const char *name_);

  protected:
    ip_resolver_options_t options;

    int resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_);
    int resolve_getaddrinfo (ip_addr_t *ip_addr_, const char *addr_);

#if defined ZMQ_HAVE_WINDOWS
    int get_interface_name (unsigned long index, char **dest) const;
    int wchar_to_utf8 (const WCHAR *src, char **dest) const;
#endif

    //  Virtual functions that are overriden in tests
    virtual int do_getaddrinfo (const char *node_,
                                const char *service_,
                                const struct addrinfo *hints_,
                                struct addrinfo **res_);

    virtual void do_freeaddrinfo (struct addrinfo *res_);

    virtual unsigned int do_if_nametoindex (const char *ifname_);
};
}

#endif
