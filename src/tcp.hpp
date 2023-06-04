/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_TCP_HPP_INCLUDED__
#define __ZMQ_TCP_HPP_INCLUDED__

#include "fd.hpp"

namespace zmq
{
class tcp_address_t;
struct options_t;

//  Tunes the supplied TCP socket for the best latency.
int tune_tcp_socket (fd_t s_);

//  Sets the socket send buffer size.
int set_tcp_send_buffer (fd_t sockfd_, int bufsize_);

//  Sets the socket receive buffer size.
int set_tcp_receive_buffer (fd_t sockfd_, int bufsize_);

//  Tunes TCP keep-alives
int tune_tcp_keepalives (fd_t s_,
                         int keepalive_,
                         int keepalive_cnt_,
                         int keepalive_idle_,
                         int keepalive_intvl_);

//  Tunes TCP max retransmit timeout
int tune_tcp_maxrt (fd_t sockfd_, int timeout_);

//  Writes data to the socket. Returns the number of bytes actually
//  written (even zero is to be considered to be a success). In case
//  of error or orderly shutdown by the other peer -1 is returned.
int tcp_write (fd_t s_, const void *data_, size_t size_);

//  Reads data from the socket (up to 'size' bytes).
//  Returns the number of bytes actually read or -1 on error.
//  Zero indicates the peer has closed the connection.
int tcp_read (fd_t s_, void *data_, size_t size_);

void tcp_tune_loopback_fast_path (fd_t socket_);

void tune_tcp_busy_poll (fd_t socket_, int busy_poll_);

//  Resolves the given address_ string, opens a socket and sets socket options
//  according to the passed options_. On success, returns the socket
//  descriptor and assigns the resolved address to out_tcp_addr_. In case of
//  an error, retired_fd is returned, and the value of out_tcp_addr_ is undefined.
//  errno is set to an error code describing the cause of the error.
fd_t tcp_open_socket (const char *address_,
                      const options_t &options_,
                      bool local_,
                      bool fallback_to_ipv4_,
                      tcp_address_t *out_tcp_addr_);
}

#endif
