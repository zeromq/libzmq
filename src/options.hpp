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

#ifndef __ZMQ_OPTIONS_HPP_INCLUDED__
#define __ZMQ_OPTIONS_HPP_INCLUDED__

#include <string>
#include <vector>
#include <map>

#include "atomic_ptr.hpp"
#include "stddef.h"
#include "stdint.hpp"
#include "tcp_address.hpp"

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
#include <set>
#include <sys/types.h>
#endif
#ifdef ZMQ_HAVE_LOCAL_PEERCRED
#include <sys/ucred.h>
#endif

#if __cplusplus >= 201103L || (defined _MSC_VER && _MSC_VER >= 1700)
#include <type_traits>
#endif

//  Normal base 256 key is 32 bytes
#define CURVE_KEYSIZE 32
//  Key encoded using Z85 is 40 bytes
#define CURVE_KEYSIZE_Z85 40

namespace zmq
{
struct options_t
{
    options_t ();

    int set_curve_key (uint8_t *destination_,
                       const void *optval_,
                       size_t optvallen_);

    int setsockopt (int option_, const void *optval_, size_t optvallen_);
    int getsockopt (int option_, void *optval_, size_t *optvallen_) const;

    //  High-water marks for message pipes.
    int sndhwm;
    int rcvhwm;

    //  I/O thread affinity.
    uint64_t affinity;

    //  Socket routing id.
    unsigned char routing_id_size;
    unsigned char routing_id[256];

    //  Maximum transfer rate [kb/s]. Default 100kb/s.
    int rate;

    //  Reliability time interval [ms]. Default 10 seconds.
    int recovery_ivl;

    // Sets the time-to-live field in every multicast packet sent.
    int multicast_hops;

    // Sets the maximum transport data unit size in every multicast
    // packet sent.
    int multicast_maxtpdu;

    // SO_SNDBUF and SO_RCVBUF to be passed to underlying transport sockets.
    int sndbuf;
    int rcvbuf;

    // Type of service (containing DSCP and ECN socket options)
    int tos;

    // Protocol-defined priority
    int priority;

    //  Socket type.
    int8_t type;

    //  Linger time, in milliseconds.
    atomic_value_t linger;

    //  Maximum interval in milliseconds beyond which userspace will
    //  timeout connect().
    //  Default 0 (unused)
    int connect_timeout;

    //  Maximum interval in milliseconds beyond which TCP will timeout
    //  retransmitted packets.
    //  Default 0 (unused)
    int tcp_maxrt;

    //  Disable reconnect under certain conditions
    //  Default 0
    int reconnect_stop;

    //  Minimum interval between attempts to reconnect, in milliseconds.
    //  Default 100ms
    int reconnect_ivl;

    //  Maximum interval between attempts to reconnect, in milliseconds.
    //  Default 0 (unused)
    int reconnect_ivl_max;

    //  Maximum backlog for pending connections.
    int backlog;

    //  Maximal size of message to handle.
    int64_t maxmsgsize;

    // The timeout for send/recv operations for this socket, in milliseconds.
    int rcvtimeo;
    int sndtimeo;

    //  If true, IPv6 is enabled (as well as IPv4)
    bool ipv6;

    //  If 1, connecting pipes are not attached immediately, meaning a send()
    //  on a socket with only connecting pipes would block
    int immediate;

    //  If 1, (X)SUB socket should filter the messages. If 0, it should not.
    bool filter;

    //  If true, the subscription matching on (X)PUB and (X)SUB sockets
    //  is reversed. Messages are sent to and received by non-matching
    //  sockets.
    bool invert_matching;

    //  If true, the routing id message is forwarded to the socket.
    bool recv_routing_id;

    // if true, router socket accepts non-zmq tcp connections
    bool raw_socket;
    bool raw_notify; //  Provide connect notifications

    //  Address of SOCKS proxy
    std::string socks_proxy_address;

    // Credentials for SOCKS proxy.
    // Conneciton method will be basic auth if username
    // is not empty, no auth otherwise.
    std::string socks_proxy_username;
    std::string socks_proxy_password;

    //  TCP keep-alive settings.
    //  Defaults to -1 = do not change socket options
    int tcp_keepalive;
    int tcp_keepalive_cnt;
    int tcp_keepalive_idle;
    int tcp_keepalive_intvl;

    // TCP accept() filters
    typedef std::vector<tcp_address_mask_t> tcp_accept_filters_t;
    tcp_accept_filters_t tcp_accept_filters;

    // IPC accept() filters
#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    typedef std::set<uid_t> ipc_uid_accept_filters_t;
    ipc_uid_accept_filters_t ipc_uid_accept_filters;
    typedef std::set<gid_t> ipc_gid_accept_filters_t;
    ipc_gid_accept_filters_t ipc_gid_accept_filters;
#endif
#if defined ZMQ_HAVE_SO_PEERCRED
    typedef std::set<pid_t> ipc_pid_accept_filters_t;
    ipc_pid_accept_filters_t ipc_pid_accept_filters;
#endif

    //  Security mechanism for all connections on this socket
    int mechanism;

    //  If peer is acting as server for PLAIN or CURVE mechanisms
    int as_server;

    //  ZAP authentication domain
    std::string zap_domain;

    //  Security credentials for PLAIN mechanism
    std::string plain_username;
    std::string plain_password;

    //  Security credentials for CURVE mechanism
    uint8_t curve_public_key[CURVE_KEYSIZE];
    uint8_t curve_secret_key[CURVE_KEYSIZE];
    uint8_t curve_server_key[CURVE_KEYSIZE];

    //  Principals for GSSAPI mechanism
    std::string gss_principal;
    std::string gss_service_principal;

    //  Name types GSSAPI principals
    int gss_principal_nt;
    int gss_service_principal_nt;

    //  If true, gss encryption will be disabled
    bool gss_plaintext;

    //  ID of the socket.
    int socket_id;

    //  If true, socket conflates outgoing/incoming messages.
    //  Applicable to dealer, push/pull, pub/sub socket types.
    //  Cannot receive multi-part messages.
    //  Ignores hwm
    bool conflate;

    //  If connection handshake is not done after this many milliseconds,
    //  close socket.  Default is 30 secs.  0 means no handshake timeout.
    int handshake_ivl;

    bool connected;
    //  If remote peer receives a PING message and doesn't receive another
    //  message within the ttl value, it should close the connection
    //  (measured in tenths of a second)
    uint16_t heartbeat_ttl;
    //  Time in milliseconds between sending heartbeat PING messages.
    int heartbeat_interval;
    //  Time in milliseconds to wait for a PING response before disconnecting
    int heartbeat_timeout;

#if defined ZMQ_HAVE_VMCI
    uint64_t vmci_buffer_size;
    uint64_t vmci_buffer_min_size;
    uint64_t vmci_buffer_max_size;
    int vmci_connect_timeout;
#endif

    //  When creating a new ZMQ socket, if this option is set the value
    //  will be used as the File Descriptor instead of allocating a new
    //  one via the socket () system call.
    int use_fd;

    // Device to bind the underlying socket to, eg. VRF or interface
    std::string bound_device;

    //  Enforce a non-empty ZAP domain requirement for PLAIN auth
    bool zap_enforce_domain;

    // Use of loopback fastpath.
    bool loopback_fastpath;

    //  Loop sent multicast packets to local sockets
    bool multicast_loop;

    //  Maximal batching size for engines with receiving functionality.
    //  So, if there are 10 messages that fit into the batch size, all of
    //  them may be read by a single 'recv' system call, thus avoiding
    //  unnecessary network stack traversals.
    int in_batch_size;
    //  Maximal batching size for engines with sending functionality.
    //  So, if there are 10 messages that fit into the batch size, all of
    //  them may be written by a single 'send' system call, thus avoiding
    //  unnecessary network stack traversals.
    int out_batch_size;

    // Use zero copy strategy for storing message content when decoding.
    bool zero_copy;

    // Router socket ZMQ_NOTIFY_CONNECT/ZMQ_NOTIFY_DISCONNECT notifications
    int router_notify;

    // Application metadata
    std::map<std::string, std::string> app_metadata;

    // Version of monitor events to emit
    int monitor_event_version;

    //  WSS Keys
    std::string wss_key_pem;
    std::string wss_cert_pem;
    std::string wss_trust_pem;
    std::string wss_hostname;
    bool wss_trust_system;

    //  Hello msg
    std::vector<unsigned char> hello_msg;
    bool can_send_hello_msg;

    //  Disconnect msg
    std::vector<unsigned char> disconnect_msg;
    bool can_recv_disconnect_msg;
};

inline bool get_effective_conflate_option (const options_t &options)
{
    // conflate is only effective for some socket types
    return options.conflate
           && (options.type == ZMQ_DEALER || options.type == ZMQ_PULL
               || options.type == ZMQ_PUSH || options.type == ZMQ_PUB
               || options.type == ZMQ_SUB);
}

int do_getsockopt (void *optval_,
                   size_t *optvallen_,
                   const void *value_,
                   size_t value_len_);

template <typename T>
int do_getsockopt (void *const optval_, size_t *const optvallen_, T value_)
{
#if __cplusplus >= 201103L && (!defined(__GNUC__) || __GNUC__ > 5)
    static_assert (std::is_trivially_copyable<T>::value,
                   "invalid use of do_getsockopt");
#endif
    return do_getsockopt (optval_, optvallen_, &value_, sizeof (T));
}

int do_getsockopt (void *optval_,
                   size_t *optvallen_,
                   const std::string &value_);

int do_setsockopt_int_as_bool_strict (const void *optval_,
                                      size_t optvallen_,
                                      bool *out_value_);

int do_setsockopt_int_as_bool_relaxed (const void *optval_,
                                       size_t optvallen_,
                                       bool *out_value_);
}

#endif
