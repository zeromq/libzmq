/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#ifndef __TESTUTIL_HPP_INCLUDED__
#define __TESTUTIL_HPP_INCLUDED__

#if defined ZMQ_CUSTOM_PLATFORM_HPP
#include "platform.hpp"
#else
#include "../src/platform.hpp"
#endif
#include "../include/zmq.h"
#include "../src/stdint.hpp"

//  This defines the settle time used in tests; raise this if we
//  get test failures on slower systems due to binds/connects not
//  settled. Tested to work reliably at 1 msec on a fast PC.
#define SETTLE_TIME 300 //  In msec
//  Commonly used buffer size for ZMQ_LAST_ENDPOINT
//  this used to be sizeof ("tcp://[::ffff:127.127.127.127]:65536"), but this
//  may be too short for ipc wildcard binds, e.g.
#define MAX_SOCKET_STRING 256

//  We need to test codepaths with non-random bind ports. List them here to
//  keep them unique, to allow parallel test runs.
#define ENDPOINT_0 "tcp://127.0.0.1:5555"
#define ENDPOINT_1 "tcp://127.0.0.1:5556"
#define ENDPOINT_2 "tcp://127.0.0.1:5557"
#define ENDPOINT_3 "tcp://127.0.0.1:5558"
#define ENDPOINT_4 "udp://127.0.0.1:5559"
#define ENDPOINT_5 "udp://127.0.0.1:5560"
#define PORT_6 5561

#undef NDEBUG

// duplicated from fd.hpp
#ifdef ZMQ_HAVE_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#define close closesocket
typedef int socket_size_t;
inline const char *as_setsockopt_opt_t (const void *opt)
{
    return static_cast<const char *> (opt);
}
#if defined _MSC_VER && _MSC_VER <= 1400
typedef UINT_PTR fd_t;
enum
{
    retired_fd = (fd_t) (~0)
};
#else
typedef SOCKET fd_t;
enum
{
    retired_fd = (fd_t) INVALID_SOCKET
};
#endif
#else
typedef size_t socket_size_t;
inline const void *as_setsockopt_opt_t (const void *opt_)
{
    return opt_;
}
typedef int fd_t;
enum
{
    retired_fd = -1
};
#endif

//  In MSVC prior to v14, snprintf is not available
//  The closest implementation is the _snprintf_s function
#if defined _MSC_VER && _MSC_VER < 1900
#define snprintf(buffer_, count_, format_, ...)                                \
    _snprintf_s (buffer_, count_, _TRUNCATE, format_, __VA_ARGS__)
#endif

#define LIBZMQ_UNUSED(object) (void) object

//  Bounce a message from client to server and back
//  For REQ/REP or DEALER/DEALER pairs only
void bounce (void *server_, void *client_);

//  Same as bounce, but expect messages to never arrive
//  for security or subscriber reasons.
void expect_bounce_fail (void *server_, void *client_);

//  Receive 0MQ string from socket and convert into C string
//  Caller must free returned string. Returns NULL if the context
//  is being terminated.
char *s_recv (void *socket_);

bool streq (const char *lhs, const char *rhs);
bool strneq (const char *lhs, const char *rhs);

extern const char *SEQ_END;

//  Sends a message composed of frames that are C strings or null frames.
//  The list must be terminated by SEQ_END.
//  Example: s_send_seq (req, "ABC", 0, "DEF", SEQ_END);

void s_send_seq (void *socket_, ...);

//  Receives message a number of frames long and checks that the frames have
//  the given data which can be either C strings or 0 for a null frame.
//  The list must be terminated by SEQ_END.
//  Example: s_recv_seq (rep, "ABC", 0, "DEF", SEQ_END);

void s_recv_seq (void *socket_, ...);


//  Sets a zero linger period on a socket and closes it.
void close_zero_linger (void *socket_);

void setup_test_environment (void);

//  Provide portable millisecond sleep
//  http://www.cplusplus.com/forum/unices/60161/
//  http://en.cppreference.com/w/cpp/thread/sleep_for

void msleep (int milliseconds_);

// check if IPv6 is available (0/false if not, 1/true if it is)
// only way to reliably check is to actually open a socket and try to bind it
int is_ipv6_available (void);

// check if tipc is available (0/false if not, 1/true if it is)
// only way to reliably check is to actually open a socket and try to bind it
// as it depends on a non-default kernel module to be already loaded
int is_tipc_available (void);

//  Wrapper around 'inet_pton' for systems that don't support it (e.g. Windows
//  XP)
int test_inet_pton (int af_, const char *src_, void *dst_);

//  Binds an ipv4 BSD socket to an ephemeral port, returns the compiled sockaddr
struct sockaddr_in bind_bsd_socket (int socket);

#endif
