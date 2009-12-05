/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_H_INCLUDED__
#define __ZMQ_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stddef.h>

//  Microsoft Visual Studio uses non-standard way to export/import symbols.
#if defined ZMQ_BUILDING_LIBZMQ_WITH_MSVC
#define ZMQ_EXPORT __declspec(dllexport)
#elif defined _MSC_VER
#define ZMQ_EXPORT __declspec(dllimport)
#else
#define ZMQ_EXPORT
#endif

////////////////////////////////////////////////////////////////////////////////
//  0MQ errors.
////////////////////////////////////////////////////////////////////////////////

//  A number random anough not to collide with different errno ranges on
//  different OSes. The assumption is that error_t is at least 32-bit type.
#define ZMQ_HAUSNUMERO 156384712

//  On Windows platform some of the standard POSIX errnos are not defined.
#ifndef ENOTSUP
#define ENOTSUP (ZMQ_HAUSNUMERO + 1)
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT (ZMQ_HAUSNUMERO + 2)
#endif
#ifndef ENOBUFS
#define ENOBUFS (ZMQ_HAUSNUMERO + 3)
#endif
#ifndef ENETDOWN
#define ENETDOWN (ZMQ_HAUSNUMERO + 4)
#endif
#ifndef EADDRINUSE
#define EADDRINUSE (ZMQ_HAUSNUMERO + 5)
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL (ZMQ_HAUSNUMERO + 6)
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED (ZMQ_HAUSNUMERO + 7)
#endif

//  Native 0MQ error codes.
#define EMTHREAD (ZMQ_HAUSNUMERO + 50)
#define EFSM (ZMQ_HAUSNUMERO + 51)
#define ENOCOMPATPROTO (ZMQ_HAUSNUMERO + 52)

//  Resolves system errors and 0MQ errors to human-readable string.
ZMQ_EXPORT const char *zmq_strerror (int errnum);

////////////////////////////////////////////////////////////////////////////////
//  0MQ message definition.
////////////////////////////////////////////////////////////////////////////////

//  Maximal size of "Very Small Message". VSMs are passed by value
//  to avoid excessive memory allocation/deallocation.
//  If VMSs larger than 255 bytes are required, type of 'vsm_size'
//  field in zmq_msg_t structure should be modified accordingly.
#define ZMQ_MAX_VSM_SIZE 30

//  Message types. These integers may be stored in 'content' member of the
//  message instead of regular pointer to the data.
#define ZMQ_DELIMITER 31
#define ZMQ_VSM 32

//  A message. If 'shared' is true, message content pointed to by 'content'
//  is shared, i.e. reference counting is used to manage its lifetime
//  rather than straighforward malloc/free. Not that 'content' is not a pointer
//  to the raw data. Rather it is pointer to zmq::msg_content_t structure
//  (see src/msg_content.hpp for its definition).
typedef struct
{
    void *content;
    unsigned char shared;
    unsigned char vsm_size;
    unsigned char vsm_data [ZMQ_MAX_VSM_SIZE];
} zmq_msg_t;

typedef void (zmq_free_fn) (void *data);

ZMQ_EXPORT int zmq_msg_init (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_init_size (zmq_msg_t *msg, size_t size);
ZMQ_EXPORT int zmq_msg_init_data (zmq_msg_t *msg, void *data,
    size_t size, zmq_free_fn *ffn);
ZMQ_EXPORT int zmq_msg_close (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_move (zmq_msg_t *dest, zmq_msg_t *src);
ZMQ_EXPORT int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);
ZMQ_EXPORT void *zmq_msg_data (zmq_msg_t *msg);
ZMQ_EXPORT size_t zmq_msg_size (zmq_msg_t *msg);

////////////////////////////////////////////////////////////////////////////////
//  0MQ infrastructure (a.k.a. context) initialisation & termination.
////////////////////////////////////////////////////////////////////////////////

#define ZMQ_POLL 1

ZMQ_EXPORT void *zmq_init (int app_threads, int io_threads, int flags);
ZMQ_EXPORT int zmq_term (void *context);

////////////////////////////////////////////////////////////////////////////////
//  0MQ socket definition.
////////////////////////////////////////////////////////////////////////////////

//  Addresses are composed of the name of the protocol to use followed by ://
//  and a protocol-specific address. Available protocols:
//
//  tcp - the address is composed of IP address and port delimited by colon
//        sign (:). The IP address can be a hostname (with 'connect') or
//        a network interface name (with 'bind'). Examples "tcp://eth0:5555",
//        "tcp://192.168.0.1:20000", "tcp://hq.mycompany.com:80".
//
//  pgm & udp - both protocols have same address format. It's network interface
//              to use, semicolon (;), multicast group IP address, colon (:) and
//              port. Examples: "pgm://eth2;224.0.0.1:8000",
//              "udp://192.168.0.111;224.1.1.1:5555".

#define ZMQ_P2P 0
#define ZMQ_PUB 1
#define ZMQ_SUB 2
#define ZMQ_REQ 3
#define ZMQ_REP 4
#define ZMQ_UPSTREAM 5
#define ZMQ_DOWNSTREAM 6

#define ZMQ_HWM 1
#define ZMQ_LWM 2
#define ZMQ_SWAP 3
#define ZMQ_AFFINITY 4
#define ZMQ_IDENTITY 5
#define ZMQ_SUBSCRIBE 6
#define ZMQ_UNSUBSCRIBE 7
#define ZMQ_RATE 8
#define ZMQ_RECOVERY_IVL 9
#define ZMQ_MCAST_LOOP 10

#define ZMQ_NOBLOCK 1
#define ZMQ_NOFLUSH 2

ZMQ_EXPORT void *zmq_socket (void *context, int type);
ZMQ_EXPORT int zmq_close (void *s);
ZMQ_EXPORT int zmq_setsockopt (void *s, int option, const void *optval,
    size_t optvallen); 
ZMQ_EXPORT int zmq_bind (void *s, const char *addr);
ZMQ_EXPORT int zmq_connect (void *s, const char *addr);
ZMQ_EXPORT int zmq_send (void *s, zmq_msg_t *msg, int flags);
ZMQ_EXPORT int zmq_flush (void *s);
ZMQ_EXPORT int zmq_recv (void *s, zmq_msg_t *msg, int flags);

////////////////////////////////////////////////////////////////////////////////
//  I/O multiplexing.
////////////////////////////////////////////////////////////////////////////////

#define ZMQ_POLLIN 1
#define ZMQ_POLLOUT 2

typedef struct
{
    void *socket;
    int fd;
    short events;
    short revents;
} zmq_pollitem_t;

ZMQ_EXPORT int zmq_poll (zmq_pollitem_t *items, int nitems);

////////////////////////////////////////////////////////////////////////////////
//  Helper functions.
////////////////////////////////////////////////////////////////////////////////

//  Helper functions are used by perf tests so that they don't have to care
//  about minutiae of time-related functions on different OS platforms.

//  Starts the stopwatch. Returns the handle to the watch.
ZMQ_EXPORT void *zmq_stopwatch_start ();

//  Stops the stopwatch. Returns the number of microseconds elapsed since
//  the stopwatch was started.
ZMQ_EXPORT unsigned long zmq_stopwatch_stop (void *watch_);

//  Sleeps for specified number of seconds.
ZMQ_EXPORT void zmq_sleep (int seconds_);

#ifdef __cplusplus
}
#endif

#endif
