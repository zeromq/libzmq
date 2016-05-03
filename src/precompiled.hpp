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

#ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
#define __ZMQ_PRECOMPILED_HPP_INCLUDED__

#ifdef _MSC_VER

// Windows headers
#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#define WIN32_LEAN_AND_MEAN		// speeds up compilation by removing rarely used windows definitions from headers
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#if defined ZMQ_HAVE_OPENBSD
#define ucred sockpeercred
#endif
#endif


// system headers
#include <intrin.h>
#include <io.h>
#include <rpc.h>
#include <sys/stat.h>
#include <assert.h>
#if defined _MSC_VER
#if defined _WIN32_WCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#endif
#endif
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_LIBGSSAPI_KRB5
#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "gssapi_server.hpp"
#include "wire.hpp"

#include <gssapi/gssapi.h>
#endif
#ifdef HAVE_LIBGSSAPI_KRB5

#if !defined(ZMQ_HAVE_FREEBSD) && !defined(ZMQ_HAVE_DRAGONFLY)
#include <gssapi/gssapi_generic.h>
#endif
#include <gssapi/gssapi_krb5.h>

#include "mechanism.hpp"
#include "options.hpp"
#include <gssapi/gssapi_krb5.h>
#endif
#if ((defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_OPENBSD ||\
    defined ZMQ_HAVE_QNXNTO || defined ZMQ_HAVE_NETBSD ||\
    defined ZMQ_HAVE_DRAGONFLY || defined ZMQ_HAVE_GNU)\
    && defined ZMQ_HAVE_IFADDRS)
#include <ifaddrs.h>
#endif
#include <intrin.h>
#include <inttypes.h>
#include <io.h>
#include <ipexport.h>
#include <iphlpapi.h>
#include <limits.h>
#include <Mstcpip.h>
#include <mswsock.h>
#include <process.h>
#include <rpc.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// standard C++ headers
#include <algorithm>
#include <atomic>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#endif // _MSC_VER


// 0MQ definitions and exported functions
#include "platform.hpp"
#include "../include/zmq.h"

/******************************************************************************/
/*  These functions are DRAFT and disabled in stable releases, and subject to */
/*  change at ANY time until declared stable.                                 */
/******************************************************************************/

#ifndef ZMQ_BUILD_DRAFT_API

/*  DRAFT Socket types.                                                       */
#define ZMQ_SERVER 12
#define ZMQ_CLIENT 13
#define ZMQ_RADIO 14
#define ZMQ_DISH 15
#define ZMQ_GATHER 16
#define ZMQ_SCATTER 17

/*  DRAFT Socket methods.                                                     */
int zmq_join (void *s, const char *group);
int zmq_leave (void *s, const char *group);

/*  DRAFT Msg methods.                                                        */
int zmq_msg_set_routing_id(zmq_msg_t *msg, uint32_t routing_id);
uint32_t zmq_msg_routing_id(zmq_msg_t *msg);
int zmq_msg_set_group(zmq_msg_t *msg, const char *group);
const char *zmq_msg_group(zmq_msg_t *msg);

/******************************************************************************/
/*  Poller polling on sockets,fd and thread-safe sockets                      */
/******************************************************************************/

#define ZMQ_HAVE_POLLER

typedef struct zmq_poller_event_t
{
    void *socket;
#if defined _WIN32
    SOCKET fd;
#else
    int fd;
#endif
    void *user_data;
    short events;
} zmq_poller_event_t;

void *zmq_poller_new (void);
int  zmq_poller_destroy (void **poller_p);
int  zmq_poller_add (void *poller, void *socket, void *user_data, short events);
int  zmq_poller_modify (void *poller, void *socket, short events);
int  zmq_poller_remove (void *poller, void *socket);
int  zmq_poller_wait (void *poller, zmq_poller_event_t *event, long timeout);

#if defined _WIN32
int zmq_poller_add_fd (void *poller, SOCKET fd, void *user_data, short events);
int zmq_poller_modify_fd (void *poller, SOCKET fd, short events);
int zmq_poller_remove_fd (void *poller, SOCKET fd);
#else
int zmq_poller_add_fd (void *poller, int fd, void *user_data, short events);
int zmq_poller_modify_fd (void *poller, int fd, short events);
int zmq_poller_remove_fd (void *poller, int fd);
#endif

/******************************************************************************/
/*  Scheduling timers                                                         */
/******************************************************************************/

#define ZMQ_HAVE_TIMERS

typedef void (zmq_timer_fn)(int timer_id, void *arg);

void *zmq_timers_new (void);
int   zmq_timers_destroy (void **timers_p);
int   zmq_timers_add (void *timers, size_t interval, zmq_timer_fn handler, void *arg);
int   zmq_timers_cancel (void *timers, int timer_id);
int   zmq_timers_set_interval (void *timers, int timer_id, size_t interval);
int   zmq_timers_reset (void *timers, int timer_id);
long  zmq_timers_timeout (void *timers);
int   zmq_timers_execute (void *timers);

#endif // ZMQ_BUILD_DRAFT_API

#endif //ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
