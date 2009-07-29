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

#ifndef __ZSOCKETS_H_INCLUDED__
#define __ZSOCKETS_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#if defined MSC_VER && defined ZS_BUILDING_LIBZS
#define ZS_EXPORT __declspec(dllexport)
#else
#define ZS_EXPORT
#endif

//  Maximal size of "Very Small Message". VSMs are passed by value
//  to avoid excessive memory allocation/deallocation.
#define ZS_MAX_VSM_SIZE 30

//  Message & notification types.
#define ZS_GAP 1
#define ZS_DELIMITER 31
#define ZS_VSM 32

//  The operation should be performed in non-blocking mode. I.e. if it cannot
//  be processed immediately, error should be returned with errno set to EAGAIN.
#define ZS_NOBLOCK 1

//  zs_send should not flush the message downstream immediately. Instead, it
//  should batch ZS_NOFLUSH messages and send them downstream only when zs_flush
//  is invoked. This is an optimisation for cases where several messages are
//  sent in a single business transaction. However, the effect is measurable
//  only in extremely high-perf scenarios (million messages a second or so).
//  If that's not your case, use standard flushing send instead. See exchange
//  example for illustration of ZS_NOFLUSH functionality.
#define ZS_NOFLUSH 2

//  Socket to communicate with a single peer. Allows for a singe connect or a
//  single accept. There's no message routing or message filtering involved.
#define ZS_P2P 0

//  Socket to distribute data. Recv fuction is not implemeted for this socket
//  type. Messages are distributed in fanout fashion to all peers.
#define ZS_PUB 1

//  Socket to subscribe to distributed data. Send function is not implemented
//  for this socket type. However, subscribe function can be used to modify the
//  message filter.
#define ZS_SUB 2

//  Socket to send requests on and receive replies from. Requests are
//  load-balanced among all the peers. This socket type doesn't allow for more
//  recv's that there were send's.
#define ZS_REQ 3

//  Socket to receive requests from and send replies to. This socket type allows
//  only an alternated sequence of recv's and send's. Each send is routed to
//  the peer that the previous recv delivered message from.
#define ZS_REP 4

//  Prototype for the message body deallocation functions.
//  It is deliberately defined in the way to comply with standard C free.
typedef void (zs_free_fn) (void *data);

//  A message. If 'shared' is true, message content pointed to by 'content'
//  is shared, i.e. reference counting is used to manage its lifetime
//  rather than straighforward malloc/free. struct zs_msg_content is
//  not declared in the API.
struct zs_msg
{
    struct zs_msg_content *content;
    unsigned char shared;
    uint16_t vsm_size;
    unsigned char vsm_data [ZS_MAX_VSM_SIZE];
};

//  TODO: Different options...
struct zs_opts
{
    uint64_t hwm;
    uint64_t lwm;
    uint64_t swap;
    uint64_t mask;
    uint64_t taskset;
    const char *identity;
    const char *args;
};

//  Initialise an empty message (zero bytes long).
ZS_EXPORT int zs_msg_init (zs_msg *msg);

//  Initialise a message 'size' bytes long.
//
//  Errors: ENOMEM - the size is too large to allocate.
ZS_EXPORT int zs_msg_init_size (zs_msg *msg, size_t size);

//  Initialise a message from an existing buffer. Message isn't copied,
//  instead 0SOCKETS infrastructure take ownership of the buffer and call
//  deallocation functio (ffn) once it's not needed anymore.
ZS_EXPORT int zs_msg_init_data (zs_msg *msg, void *data, size_t size,
    zs_free_fn *ffn);

//  Deallocate the message.
ZS_EXPORT int zs_msg_close (zs_msg *msg);

//  Move the content of the message from 'src' to 'dest'. The content isn't
//  copied, just moved. 'src' is an empty message after the call. Original
//  content of 'dest' message is deallocated.
ZS_EXPORT int zs_msg_move (zs_msg *dest, zs_msg *src);

//  Copy the 'src' message to 'dest'. The content isn't copied, instead
//  reference count is increased. Don't modify the message data after the
//  call as they are shared between two messages. Original content of 'dest'
//  message is deallocated.
ZS_EXPORT int zs_msg_copy (zs_msg *dest, zs_msg *src);

//  Returns pointer to message data.
ZS_EXPORT void *zs_msg_data (zs_msg *msg);

//  Return size of message data (in bytes).
ZS_EXPORT size_t zs_msg_size (zs_msg *msg);

//  Returns type of the message.
ZS_EXPORT int zs_msg_type (zs_msg *msg);

//  Initialise 0SOCKETS context. 'app_threads' specifies maximal number
//  of application threads that can have open sockets at the same time.
//  'io_threads' specifies the size of thread pool to handle I/O operations.
//
//  Errors: EINVAL - one of the arguments is less than zero or there are no
//                   threads declared at all.
ZS_EXPORT void *zs_init (int app_threads, int io_threads);

//  Deinitialise 0SOCKETS context including all the open sockets. Closing
//  sockets after zs_term has been called will result in undefined behaviour.
ZS_EXPORT int zs_term (void *context);

//  Open a socket.
//
//  Errors: EINVAL - invalid socket type.
//          EMFILE - the number of application threads entitled to hold open
//                   sockets at the same time was exceeded.
ZS_EXPORT void *zs_socket (void *context, int type);

//  Close the socket.
ZS_EXPORT int zs_close (void *s);

//  Bind the socket to a particular address.
ZS_EXPORT int zs_bind (void *s, const char *addr, zs_opts *opts);

//  Connect the socket to a particular address.
ZS_EXPORT int zs_connect (void *s, const char *addr, zs_opts *opts);

//  Subscribe for the subset of messages identified by 'criteria' argument.
ZS_EXPORT int zs_subscribe (void *s, const char *criteria);

//  Send the message 'msg' to the socket 's'. 'flags' argument can be
//  combination of following values:
//  ZS_NOBLOCK - if message cannot be sent, return immediately.
//  ZS_NOFLUSH - message won't be sent immediately. It'll be sent with either
//               subsequent flushing send or explicit call to zs_flush function.
//
//  Errors: EAGAIN - message cannot be sent at the moment (applies only to
//                   non-blocking send).
//          ENOTSUP - function isn't supported by particular socket type.
ZS_EXPORT int zs_send (void *s, zs_msg *msg, int flags);

//  Flush the messages that were send using ZS_NOFLUSH flag down the stream.
//
//  Errors: ENOTSUP - function isn't supported by particular socket type.
ZS_EXPORT int zs_flush (void *s);

//  Send a message from the socket 's'. 'flags' argument can be combination
//  of following values:
//  ZS_NOBLOCK - if message cannot be received, return immediately.
//
//  Errors: EAGAIN - message cannot be received at the moment (applies only to
//                   non-blocking receive).
//          ENOTSUP - function isn't supported by particular socket type.
ZS_EXPORT int zs_recv (void *s, zs_msg *msg, int flags);

#ifdef __cplusplus
}
#endif

#endif
