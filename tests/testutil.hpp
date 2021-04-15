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

//  For AF_INET and IPPROTO_TCP
#if defined _WIN32
#include "../src/windows.hpp"
#if defined(__MINGW32__)
#include <unistd.h>
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#endif

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

//  For tests that mock ZMTP
const uint8_t zmtp_greeting_null[64] = {
  0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 3, 0, 'N', 'U', 'L', 'L',
  0,    0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0,
  0,    0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0};

const uint8_t zmtp_greeting_curve[64] = {
  0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0x7f, 3, 0, 'C', 'U', 'R', 'V',
  'E',  0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0,
  0,    0, 0, 0, 0, 0, 0, 0, 0, 0,    0, 0, 0,   0,   0,   0};
const uint8_t zmtp_ready_dealer[43] = {
  4,   41,  5,   'R', 'E', 'A', 'D', 'Y', 11,  'S', 'o', 'c', 'k', 'e', 't',
  '-', 'T', 'y', 'p', 'e', 0,   0,   0,   6,   'D', 'E', 'A', 'L', 'E', 'R',
  8,   'I', 'd', 'e', 'n', 't', 'i', 't', 'y', 0,   0,   0,   0};
const uint8_t zmtp_ready_xpub[28] = {
  4,   26,  5,   'R', 'E', 'A', 'D', 'Y', 11, 'S', 'o', 'c', 'k', 'e',
  't', '-', 'T', 'y', 'p', 'e', 0,   0,   0,  4,   'X', 'P', 'U', 'B'};
const uint8_t zmtp_ready_sub[27] = {
  4,   25,  5,   'R', 'E', 'A', 'D', 'Y', 11, 'S', 'o', 'c', 'k', 'e',
  't', '-', 'T', 'y', 'p', 'e', 0,   0,   0,  3,   'S', 'U', 'B'};

#undef NDEBUG

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// duplicated from fd.hpp
#ifdef ZMQ_HAVE_WINDOWS
#ifndef NOMINMAX
#define NOMINMAX // Macros min(a,b) and max(a,b)
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#define close closesocket
typedef int socket_size_t;
inline const char *as_setsockopt_opt_t (const void *opt)
{
    return static_cast<const char *> (opt);
}
#else
typedef size_t socket_size_t;
inline const void *as_setsockopt_opt_t (const void *opt_)
{
    return opt_;
}
#endif

// duplicated from fd.hpp
typedef zmq_fd_t fd_t;
#ifdef ZMQ_HAVE_WINDOWS
#if defined _MSC_VER && _MSC_VER <= 1400
enum
{
    retired_fd = (zmq_fd_t) (~0)
};
#else
enum
#if _MSC_VER >= 1800
  : zmq_fd_t
#endif
{
    retired_fd = INVALID_SOCKET
};
#endif
#else
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

//  Setups the test environment. Must be called at the beginning of each test
//  executable. On POSIX systems, it sets an alarm to the specified number of
//  seconds, after which the test will be killed. Set to 0 to disable this
//  timeout.
void setup_test_environment (int timeout_seconds_ = 60);

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

//  Some custom definitions in addition to IPPROTO_TCP and IPPROTO_UDP
#define IPPROTO_WS 10000
#define IPPROTO_WSS 10001

//  Connects a BSD socket to the ZMQ endpoint. Works with ipv4/ipv6/unix.
fd_t connect_socket (const char *endpoint_,
                     const int af_ = AF_INET,
                     const int protocol_ = IPPROTO_TCP);

//  Binds a BSD socket to an ephemeral port, returns the file descriptor.
//  The resulting ZMQ endpoint will be stored in my_endpoint, including the protocol
//  prefix, so ensure it is writable and of appropriate size.
//  Works with ipv4/ipv6/unix. With unix sockets address_/port_ can be empty and
//  my_endpoint_ will contain a random path.
fd_t bind_socket_resolve_port (const char *address_,
                               const char *port_,
                               char *my_endpoint_,
                               const int af_ = AF_INET,
                               const int protocol_ = IPPROTO_TCP);

int fuzzer_corpus_encode (const char *filename,
                          uint8_t ***data,
                          size_t **len,
                          size_t *num_cases);

#endif
