/* SPDX-License-Identifier: MPL-2.0 */

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
void set_ip_type_of_service (fd_t s_, int iptos_);

// Sets the protocol-defined priority for the underlying socket
void set_socket_priority (fd_t s_, int priority_);

// Sets the SO_NOSIGPIPE option for the underlying socket.
// Return 0 on success, -1 if the connection has been closed by the peer
int set_nosigpipe (fd_t s_);

// Binds the underlying socket to the given device, eg. VRF or interface
int bind_to_device (fd_t s_, const std::string &bound_device_);

// Initialize network subsystem. May be called multiple times. Each call must be matched by a call to shutdown_network.
bool initialize_network ();

// Shutdown network subsystem. Must be called once for each call to initialize_network before terminating.
void shutdown_network ();

// Creates a pair of sockets (using signaler_port on OS using TCP sockets).
// Returns -1 if we could not make the socket pair successfully
int make_fdpair (fd_t *r_, fd_t *w_);

// Makes a socket non-inheritable to child processes.
// Asserts on any failure.
void make_socket_noninheritable (fd_t sock_);

//  Asserts that:
//  - an internal 0MQ error did not occur,
//  - and, if a socket error occurred, it can be recovered from.
void assert_success_or_recoverable (fd_t s_, int rc_);

#ifdef ZMQ_HAVE_IPC
// Create an IPC wildcard path address
int create_ipc_wildcard_address (std::string &path_, std::string &file_);
#endif
}

#endif
