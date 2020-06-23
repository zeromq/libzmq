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

#ifndef __ZMQ_ADDRESS_HPP_INCLUDED__
#define __ZMQ_ADDRESS_HPP_INCLUDED__

#include "fd.hpp"

#include <string>

#ifndef ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#else
#include <ws2tcpip.h>
#endif

namespace zmq
{
class ctx_t;
class tcp_address_t;
class udp_address_t;
class ws_address_t;
#ifdef ZMQ_HAVE_WSS
class wss_address_t;
#endif
#if defined ZMQ_HAVE_IPC
class ipc_address_t;
#endif
#if defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_VXWORKS
class tipc_address_t;
#endif
#if defined ZMQ_HAVE_VMCI
class vmci_address_t;
#endif

namespace protocol_name
{
static const char inproc[] = "inproc";
static const char tcp[] = "tcp";
static const char udp[] = "udp";
#ifdef ZMQ_HAVE_OPENPGM
static const char pgm[] = "pgm";
static const char epgm[] = "epgm";
#endif
#ifdef ZMQ_HAVE_NORM
static const char norm[] = "norm";
#endif
#ifdef ZMQ_HAVE_WS
static const char ws[] = "ws";
#endif
#ifdef ZMQ_HAVE_WSS
static const char wss[] = "wss";
#endif
#if defined ZMQ_HAVE_IPC
static const char ipc[] = "ipc";
#endif
#if defined ZMQ_HAVE_TIPC
static const char tipc[] = "tipc";
#endif
#if defined ZMQ_HAVE_VMCI
static const char vmci[] = "vmci";
#endif
}

struct address_t
{
    address_t (const std::string &protocol_,
               const std::string &address_,
               ctx_t *parent_);

    ~address_t ();

    const std::string protocol;
    const std::string address;
    ctx_t *const parent;

    //  Protocol specific resolved address
    //  All members must be pointers to allow for consistent initialization
    union
    {
        void *dummy;
        tcp_address_t *tcp_addr;
        udp_address_t *udp_addr;
#ifdef ZMQ_HAVE_WS
        ws_address_t *ws_addr;
#endif
#ifdef ZMQ_HAVE_WSS
        wss_address_t *wss_addr;
#endif
#if defined ZMQ_HAVE_IPC
        ipc_address_t *ipc_addr;
#endif
#if defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_VXWORKS
        tipc_address_t *tipc_addr;
#endif
#if defined ZMQ_HAVE_VMCI
        vmci_address_t *vmci_addr;
#endif
    } resolved;

    int to_string (std::string &addr_) const;
};

#if defined(ZMQ_HAVE_HPUX) || defined(ZMQ_HAVE_VXWORKS)                        \
  || defined(ZMQ_HAVE_WINDOWS)
typedef int zmq_socklen_t;
#else
typedef socklen_t zmq_socklen_t;
#endif

enum socket_end_t
{
    socket_end_local,
    socket_end_remote
};

zmq_socklen_t
get_socket_address (fd_t fd_, socket_end_t socket_end_, sockaddr_storage *ss_);

template <typename T>
std::string get_socket_name (fd_t fd_, socket_end_t socket_end_)
{
    struct sockaddr_storage ss;
    const zmq_socklen_t sl = get_socket_address (fd_, socket_end_, &ss);
    if (sl == 0) {
        return std::string ();
    }

    const T addr (reinterpret_cast<struct sockaddr *> (&ss), sl);
    std::string address_string;
    addr.to_string (address_string);
    return address_string;
}
}

#endif
