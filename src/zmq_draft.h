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

#ifndef __ZMQ_DRAFT_H_INCLUDED__
#define __ZMQ_DRAFT_H_INCLUDED__

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
#define ZMQ_DGRAM 18

/*  DRAFT 0MQ socket events and monitoring                                    */
#define ZMQ_EVENT_HANDSHAKE_FAILED  0x0800
#define ZMQ_EVENT_HANDSHAKE_SUCCEED 0x1000

/*  DRAFT Context options                                                     */
#define ZMQ_MSG_T_SIZE 6

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
int  zmq_poller_wait_all (void *poller, zmq_poller_event_t *events, int n_events, long timeout);

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

typedef void (zmq_timer_fn)(int timer_id, void *arg);

void *zmq_timers_new (void);
int   zmq_timers_destroy (void **timers_p);
int   zmq_timers_add (void *timers, size_t interval, zmq_timer_fn handler, void *arg);
int   zmq_timers_cancel (void *timers, int timer_id);
int   zmq_timers_set_interval (void *timers, int timer_id, size_t interval);
int   zmq_timers_reset (void *timers, int timer_id);
long  zmq_timers_timeout (void *timers);
int   zmq_timers_execute (void *timers);

/******************************************************************************/
/*  GSSAPI socket options to set name type                                    */
/******************************************************************************/

#define ZMQ_GSSAPI_PRINCIPAL_NAMETYPE 90
#define ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE 91

/*  GSSAPI principal name types                                               */
#define ZMQ_GSSAPI_NT_HOSTBASED 0
#define ZMQ_GSSAPI_NT_USER_NAME 1
#define ZMQ_GSSAPI_NT_KRB5_PRINCIPAL 2

#endif // ZMQ_BUILD_DRAFT_API

#endif //ifndef __ZMQ_DRAFT_H_INCLUDED__
