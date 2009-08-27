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

#include <stddef.h>
#include <stdint.h>

#if defined MSC_VER && defined ZMQ_BUILDING_LIBZMQ
#define ZMQ_EXPORT __declspec(dllexport)
#else
#define ZMQ_EXPORT
#endif

//  Maximal size of "Very Small Message". VSMs are passed by value
//  to avoid excessive memory allocation/deallocation.
#define ZMQ_MAX_VSM_SIZE 30

//  Message & notification types.
#define ZMQ_GAP 1
#define ZMQ_DELIMITER 31
#define ZMQ_VSM 32

//  Socket options.
#define ZMQ_HWM 1
#define ZMQ_LWM 2
#define ZMQ_SWAP 3
#define ZMQ_MASK 4
#define ZMQ_AFFINITY 5
#define ZMQ_IDENTITY 6

//  The operation should be performed in non-blocking mode. I.e. if it cannot
//  be processed immediately, error should be returned with errno set to EAGAIN.
#define ZMQ_NOBLOCK 1

//  zmq_send should not flush the message downstream immediately. Instead, it
//  should batch ZMQ_NOFLUSH messages and send them downstream only if zmq_flush
//  is invoked. This is an optimisation for cases where several messages are
//  sent in a single business transaction. However, the effect is measurable
//  only in extremely high-perf scenarios (million messages a second or so).
//  If that's not your case, use standard flushing send instead. See exchange
//  example for illustration of ZMQ_NOFLUSH functionality.
#define ZMQ_NOFLUSH 2

//  Socket to communicate with a single peer. Allows for a singe connect or a
//  single accept. There's no message routing or message filtering involved.
#define ZMQ_P2P 0

//  Socket to distribute data. Recv fuction is not implemented for this socket
//  type. Messages are distributed in fanout fashion to all peers.
#define ZMQ_PUB 1

//  Socket to subscribe to distributed data. Send function is not implemented
//  for this socket type. However, subscribe function can be used to modify the
//  message filter.
#define ZMQ_SUB 2

//  Socket to send requests on and receive replies from. Requests are
//  load-balanced among all the peers. This socket type doesn't allow for more
//  recv's that there were send's.
#define ZMQ_REQ 3

//  Socket to receive requests from and send replies to. This socket type allows
//  only an alternated sequence of recv's and send's. Each send is routed to
//  the peer that the previous recv delivered message from.
#define ZMQ_REP 4

//  Prototype for the message body deallocation functions.
//  It is deliberately defined in the way to comply with standard C free.
typedef void (zmq_free_fn) (void *data);

//  A message. If 'shared' is true, message content pointed to by 'content'
//  is shared, i.e. reference counting is used to manage its lifetime
//  rather than straighforward malloc/free. struct zmq_msg_content is
//  not declared in the API.
struct zmq_msg_t
{
    void *content;
    unsigned char shared;
    uint16_t vsm_size;
    unsigned char vsm_data [ZMQ_MAX_VSM_SIZE];
};

//  Initialise an empty message (zero bytes long).
ZMQ_EXPORT int zmq_msg_init (zmq_msg_t *msg);

//  Initialise a message 'size' bytes long.
//
//  Errors: ENOMEM - the size is too large to allocate.
ZMQ_EXPORT int zmq_msg_init_size (zmq_msg_t *msg, size_t size);

//  Initialise a message from an existing buffer. Message isn't copied,
//  instead 0SOCKETS infrastructure take ownership of the buffer and call
//  deallocation functio (ffn) once it's not needed anymore.
ZMQ_EXPORT int zmq_msg_init_data (zmq_msg_t *msg, void *data, size_t size,
    zmq_free_fn *ffn);

//  Deallocate the message.
ZMQ_EXPORT int zmq_msg_close (zmq_msg_t *msg);

//  Move the content of the message from 'src' to 'dest'. The content isn't
//  copied, just moved. 'src' is an empty message after the call. Original
//  content of 'dest' message is deallocated.
ZMQ_EXPORT int zmq_msg_move (zmq_msg_t *dest, zmq_msg_t *src);

//  Copy the 'src' message to 'dest'. The content isn't copied, instead
//  reference count is increased. Don't modify the message data after the
//  call as they are shared between two messages. Original content of 'dest'
//  message is deallocated.
ZMQ_EXPORT int zmq_msg_copy (zmq_msg_t *dest, zmq_msg_t *src);

//  Returns pointer to message data.
ZMQ_EXPORT void *zmq_msg_data (zmq_msg_t *msg);

//  Return size of message data (in bytes).
ZMQ_EXPORT size_t zmq_msg_size (zmq_msg_t *msg);

//  Returns type of the message.
ZMQ_EXPORT int zmq_msg_type (zmq_msg_t *msg);

//  Initialise 0SOCKETS context. 'app_threads' specifies maximal number
//  of application threads that can have open sockets at the same time.
//  'io_threads' specifies the size of thread pool to handle I/O operations.
//
//  Errors: EINVAL - one of the arguments is less than zero or there are no
//                   threads declared at all.
ZMQ_EXPORT void *zmq_init (int app_threads, int io_threads);

//  Deinitialise 0SOCKETS context including all the open sockets. Closing
//  sockets after zmq_term has been called will result in undefined behaviour.
ZMQ_EXPORT int zmq_term (void *context);

//  Open a socket.
//
//  Errors: EINVAL - invalid socket type.
//          EMFILE - the number of application threads entitled to hold open
//                   sockets at the same time was exceeded.
ZMQ_EXPORT void *zmq_socket (void *context, int type);

//  Close the socket.
ZMQ_EXPORT int zmq_close (void *s);

//  Sets an option on the socket.
//  EINVAL - unknown option, a value with incorrect length or an invalid value.
ZMQ_EXPORT int zmq_setsockopt (void *s, int option_, const void *optval_,
    size_t optvallen_); 

//  Bind the socket to a particular address.
ZMQ_EXPORT int zmq_bind (void *s, const char *addr);

//  Connect the socket to a particular address.
ZMQ_EXPORT int zmq_connect (void *s, const char *addr);

//  Send the message 'msg' to the socket 's'. 'flags' argument can be
//  combination of following values:
//  ZMQ_NOBLOCK - if message cannot be sent, return immediately.
//  ZMQ_NOFLUSH - message won't be sent immediately. It'll be sent with either
//                subsequent flushing send or explicit call to zmq_flush
//                function.
//
//  Errors: EAGAIN - message cannot be sent at the moment (applies only to
//                   non-blocking send).
//          ENOTSUP - function isn't supported by particular socket type.
ZMQ_EXPORT int zmq_send (void *s, zmq_msg_t *msg, int flags);

//  Flush the messages that were send using ZMQ_NOFLUSH flag down the stream.
//
//  Errors: ENOTSUP - function isn't supported by particular socket type.
ZMQ_EXPORT int zmq_flush (void *s);

//  Send a message from the socket 's'. 'flags' argument can be combination
//  of following values:
//  ZMQ_NOBLOCK - if message cannot be received, return immediately.
//
//  Errors: EAGAIN - message cannot be received at the moment (applies only to
//                   non-blocking receive).
//          ENOTSUP - function isn't supported by particular socket type.
ZMQ_EXPORT int zmq_recv (void *s, zmq_msg_t *msg, int flags);

#ifdef __cplusplus
}
#endif

#endif
