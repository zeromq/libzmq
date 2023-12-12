/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_HVSOCKET_HPP_INCLUDED__
#define __ZMQ_HVSOCKET_HPP_INCLUDED__

#include <string>

#include "platform.hpp"
#include "fd.hpp"
#include "ctx.hpp"

#if defined ZMQ_HAVE_HVSOCKET

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <sys/time.h>
#endif

namespace zmq
{
void tune_hvsocket_buffer_size (ctx_t *context_,
                            fd_t sockfd_,
                            uint64_t default_size_,
                            uint64_t min_size_,
                            uint64_t max_size_);

#if defined ZMQ_HAVE_WINDOWS
void tune_hvsocket_connect_timeout (ctx_t *context_, fd_t sockfd_, DWORD timeout_);
#else
void tune_hvsocket_connect_timeout (ctx_t *context_,
                                fd_t sockfd_,
                                struct timeval timeout_);
#endif

fd_t hvsocket_open_socket (const char *address_,
                       const options_t &options_,
                       hvsocket_address_t *out_hvsocket_addr_);
}

#endif

#endif
