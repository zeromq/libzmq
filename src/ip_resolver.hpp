/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_IP_RESOLVER_HPP_INCLUDED__
#define __ZMQ_IP_RESOLVER_HPP_INCLUDED__

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "address.hpp"

namespace zmq
{
union ip_addr_t
{
    sockaddr generic;
    sockaddr_in ipv4;
    sockaddr_in6 ipv6;

    int family () const;
    bool is_multicast () const;
    uint16_t port () const;

    const struct sockaddr *as_sockaddr () const;
    zmq_socklen_t sockaddr_len () const;

    void set_port (uint16_t);

    static ip_addr_t any (int family_);
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
    ip_resolver_options_t &allow_path (bool allow_);

    bool bindable ();
    bool allow_nic_name ();
    bool ipv6 ();
    bool expect_port ();
    bool allow_dns ();
    bool allow_path ();

  private:
    bool _bindable_wanted;
    bool _nic_name_allowed;
    bool _ipv6_wanted;
    bool _port_expected;
    bool _dns_allowed;
    bool _path_allowed;
};

class ip_resolver_t
{
  public:
    ip_resolver_t (ip_resolver_options_t opts_);
    virtual ~ip_resolver_t (){};

    int resolve (ip_addr_t *ip_addr_, const char *name_);

  protected:
    //  Virtual functions that are overridden in tests
    virtual int do_getaddrinfo (const char *node_,
                                const char *service_,
                                const struct addrinfo *hints_,
                                struct addrinfo **res_);

    virtual void do_freeaddrinfo (struct addrinfo *res_);

    virtual unsigned int do_if_nametoindex (const char *ifname_);

  private:
    ip_resolver_options_t _options;

    int resolve_nic_name (ip_addr_t *ip_addr_, const char *nic_);
    int resolve_getaddrinfo (ip_addr_t *ip_addr_, const char *addr_);

#if defined ZMQ_HAVE_WINDOWS
    int get_interface_name (unsigned long index_, char **dest_) const;
    int wchar_to_utf8 (const WCHAR *src_, char **dest_) const;
#endif
};
}

#endif
