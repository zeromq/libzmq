/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_H_INCLUDED__
#define __ZMQ_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#if defined _WIN32
#include <winsock2.h>
#endif

/*  Handle DSO symbol visibility                                             */
#if defined _WIN32
#   if defined DLL_EXPORT
#       define ZMQ_EXPORT __declspec(dllexport)
#   else
#       define ZMQ_EXPORT __declspec(dllimport)
#   endif
#else
#   if defined __SUNPRO_C  || defined __SUNPRO_CC
#       define ZMQ_EXPORT __global
#   elif (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define ZMQ_EXPORT __attribute__ ((visibility("default")))
#   else
#       define ZMQ_EXPORT
#   endif
#endif

/******************************************************************************/
/*  0MQ versioning support.                                                   */
/******************************************************************************/

/*  Version macros for compile-time API version detection                     */
#define ZMQ_VERSION_MAJOR 3
#define ZMQ_VERSION_MINOR 1
#define ZMQ_VERSION_PATCH 1

#define ZMQ_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define ZMQ_VERSION \
    ZMQ_MAKE_VERSION(ZMQ_VERSION_MAJOR, ZMQ_VERSION_MINOR, ZMQ_VERSION_PATCH)

/* ensure one of ZMQ_TYPE_SAFE/UNSAFE is defined */
/* Choose default based on version */

/* Uncomment to test */
/* #define ZMQ_EMULATE_TYPE_SAFE */

#if !defined(ZMQ_TYPE_SAFE) && !defined(ZMQ_TYPE_UNSAFE)
#   if ZMQ_VERSION_MAJOR <= 3
#       if defined ZMQ_EMULATE_TYPE_SAFE
#       else
#           define ZMQ_TYPE_UNSAFE 
#       endif
#    else
#        define ZMQ_TYPE_SAFE
#    endif
#elif defined(ZMQ_TYPE_SAFE) && defined(ZMQ_TYPE_UNSAFE)
#     error "BOTH ZMQ_TYPE_SAFE and ZMQ_TYPE_UNSAFE are defined!"
#endif
   
#ifdef ZMQ_TYPE_UNSAFE
typedef void *zmq_socket_t;
typedef void *zmq_ctx_t;
#else
typedef struct zmq_socket_t { void *data; } zmq_socket_t;
typedef struct zmq_ctx_t { void *data; } zmq_ctx_t;
#endif

/*  Run-time API version detection                                            */
ZMQ_EXPORT void zmq_version (int *major, int *minor, int *patch);

/******************************************************************************/
/*  0MQ errors.                                                               */
/******************************************************************************/

/*  A number random enough not to collide with different errno ranges on      */
/*  different OSes. The assumption is that error_t is at least 32-bit type.   */
#define ZMQ_HAUSNUMERO 156384712

/*  On Windows platform some of the standard POSIX errnos are not defined.    */
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
#ifndef EINPROGRESS
#define EINPROGRESS (ZMQ_HAUSNUMERO + 8)
#endif
#ifndef ENOTSOCK
#define ENOTSOCK (ZMQ_HAUSNUMERO + 9)
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT (ZMQ_HAUSNUMERO + 10)
#endif

/*  Native 0MQ error codes.                                                   */
#define EFSM (ZMQ_HAUSNUMERO + 51)
#define ENOCOMPATPROTO (ZMQ_HAUSNUMERO + 52)
#define ETERM (ZMQ_HAUSNUMERO + 53)
#define EMTHREAD (ZMQ_HAUSNUMERO + 54)

/*  This function retrieves the errno as it is known to 0MQ library. The goal */
/*  of this function is to make the code 100% portable, including where 0MQ   */
/*  compiled with certain CRT library (on Windows) is linked to an            */
/*  application that uses different CRT library.                              */
ZMQ_EXPORT int zmq_errno (void);

/*  Resolves system errors and 0MQ errors to human-readable string.           */
ZMQ_EXPORT const char *zmq_strerror (int errnum);

/******************************************************************************/
/*  0MQ message definition.                                                   */
/******************************************************************************/

typedef struct {unsigned char _ [32];} zmq_msg_t;

typedef void (zmq_free_fn) (void *data, void *hint);

ZMQ_EXPORT int zmq_msg_init (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_init_size (zmq_msg_t *msg, size_t size);
ZMQ_EXPORT int zmq_msg_init_data (zmq_msg_t *msg, void *data,
    size_t size, zmq_free_fn *ffn, void *hint);
ZMQ_EXPORT int zmq_msg_send (zmq_msg_t *msg, zmq_socket_t s, int flags);
ZMQ_EXPORT int zmq_msg_recv (zmq_msg_t *msg, zmq_socket_t s, int flags);
ZMQ_EXPORT int zmq_msg_close (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_move (zmq_msg_t *dest, zmq_msg_t *src);
ZMQ_EXPORT int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);
ZMQ_EXPORT void *zmq_msg_data (zmq_msg_t *msg);
ZMQ_EXPORT size_t zmq_msg_size (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_more (zmq_msg_t *msg);
ZMQ_EXPORT int zmq_msg_get (zmq_msg_t *msg, int option, void *optval,
                            size_t *optvallen);
ZMQ_EXPORT int zmq_msg_set (zmq_msg_t *msg, int option, const void *optval,
                            size_t *optvallen);

/******************************************************************************/
/*  0MQ infrastructure (a.k.a. context) initialisation & termination.         */
/******************************************************************************/

ZMQ_EXPORT zmq_ctx_t zmq_init (int io_threads);
ZMQ_EXPORT int zmq_term (zmq_ctx_t context);

/******************************************************************************/
/*  0MQ socket definition.                                                    */
/******************************************************************************/

/*  Socket types.                                                             */ 
#define ZMQ_PAIR 0
#define ZMQ_PUB 1
#define ZMQ_SUB 2
#define ZMQ_REQ 3
#define ZMQ_REP 4
#define ZMQ_DEALER 5
#define ZMQ_ROUTER 6
#define ZMQ_PULL 7
#define ZMQ_PUSH 8
#define ZMQ_XPUB 9
#define ZMQ_XSUB 10

/*  Deprecated aliases                                                        */
#define ZMQ_XREQ ZMQ_DEALER
#define ZMQ_XREP ZMQ_ROUTER

/*  Socket options.                                                           */
#define ZMQ_AFFINITY 4
#define ZMQ_IDENTITY 5
#define ZMQ_SUBSCRIBE 6
#define ZMQ_UNSUBSCRIBE 7
#define ZMQ_RATE 8
#define ZMQ_RECOVERY_IVL 9
#define ZMQ_SNDBUF 11
#define ZMQ_RCVBUF 12
#define ZMQ_RCVMORE 13
#define ZMQ_FD 14
#define ZMQ_EVENTS 15
#define ZMQ_TYPE 16
#define ZMQ_LINGER 17
#define ZMQ_RECONNECT_IVL 18
#define ZMQ_BACKLOG 19
#define ZMQ_RECONNECT_IVL_MAX 21
#define ZMQ_MAXMSGSIZE 22
#define ZMQ_SNDHWM 23
#define ZMQ_RCVHWM 24
#define ZMQ_MULTICAST_HOPS 25
#define ZMQ_RCVTIMEO 27
#define ZMQ_SNDTIMEO 28
#define ZMQ_IPV4ONLY 31
#define ZMQ_LAST_ENDPOINT 32

/*  Message options                                                           */
#define ZMQ_MORE 1

/*  Send/recv options.                                                        */
#define ZMQ_DONTWAIT 1
#define ZMQ_SNDMORE 2

ZMQ_EXPORT zmq_socket_t zmq_socket (zmq_ctx_t context, int type);
ZMQ_EXPORT int zmq_close (zmq_socket_t s);
ZMQ_EXPORT int zmq_setsockopt (zmq_socket_t s, int option, const void *optval,
    size_t optvallen); 
ZMQ_EXPORT int zmq_getsockopt (zmq_socket_t s, int option, void *optval,
    size_t *optvallen);
ZMQ_EXPORT int zmq_bind (zmq_socket_t s, const char *addr);
ZMQ_EXPORT int zmq_connect (zmq_socket_t s, const char *addr);
ZMQ_EXPORT int zmq_send (zmq_socket_t s, const void *buf, size_t len, int flags);
ZMQ_EXPORT int zmq_recv (zmq_socket_t s, void *buf, size_t len, int flags);

ZMQ_EXPORT int zmq_sendmsg (zmq_socket_t s, zmq_msg_t *msg, int flags);
ZMQ_EXPORT int zmq_recvmsg (zmq_socket_t s, zmq_msg_t *msg, int flags);

/*  Experimental                                                              */
ZMQ_EXPORT int zmq_sendiov (zmq_socket_t s, struct iovec *iov, size_t count, int flags);
ZMQ_EXPORT int zmq_recviov (zmq_socket_t s, struct iovec *iov, size_t *count, int flags);

/******************************************************************************/
/*  I/O multiplexing.                                                         */
/******************************************************************************/

#define ZMQ_POLLIN 1
#define ZMQ_POLLOUT 2
#define ZMQ_POLLERR 4

typedef struct
{
    zmq_socket_t socket;
#if defined _WIN32
    SOCKET fd;
#else
    int fd;
#endif
    short events;
    short revents;
} zmq_pollitem_t;

ZMQ_EXPORT int zmq_poll (zmq_pollitem_t *items, int nitems, long timeout);

#undef ZMQ_EXPORT

#ifdef __cplusplus
}
#endif

#endif

