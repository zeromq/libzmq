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

#define EMTHREAD (ZMQ_HAUSNUMERO + 1)
#define EFSM (ZMQ_HAUSNUMERO + 2)
#define ENOCOMPATPROTO (ZMQ_HAUSNUMERO + 3)

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
struct zmq_msg_t
{
    void *content;
    unsigned char shared;
    unsigned char vsm_size;
    unsigned char vsm_data [ZMQ_MAX_VSM_SIZE];
};

//  Initialise an empty message (zero bytes long).
ZMQ_EXPORT int zmq_msg_init (struct zmq_msg_t *msg);

//  Initialise a message 'size' bytes long.
//
//  Errors: ENOMEM - message is too big to fit into memory.
ZMQ_EXPORT int zmq_msg_init_size (struct zmq_msg_t *msg, size_t size);

//  Initialise a message from an existing buffer. Message isn't copied,
//  instead 0MQ infrastructure takes ownership of the buffer and
//  deallocation function (ffn) will be called once the data are not
//  needed anymore. Note that deallocation function prototype is designed
//  so that it complies with standard C 'free' function.
typedef void (zmq_free_fn) (void *data);
ZMQ_EXPORT int zmq_msg_init_data (struct zmq_msg_t *msg, void *data,
    size_t size, zmq_free_fn *ffn);

//  Deallocate the message.
ZMQ_EXPORT int zmq_msg_close (struct zmq_msg_t *msg);

//  Move the content of the message from 'src' to 'dest'. The content isn't
//  copied, just moved. 'src' is an empty message after the call. Original
//  content of 'dest' message is deallocated.
ZMQ_EXPORT int zmq_msg_move (struct zmq_msg_t *dest, struct zmq_msg_t *src);

//  Copy the 'src' message to 'dest'. The content isn't copied, instead
//  reference count is increased. Don't modify the message data after the
//  call as they are shared between two messages. Original content of 'dest'
//  message is deallocated.
ZMQ_EXPORT int zmq_msg_copy (struct zmq_msg_t *dest, struct zmq_msg_t *src);

//  Returns pointer to message data.
ZMQ_EXPORT void *zmq_msg_data (struct zmq_msg_t *msg);

//  Return size of message data (in bytes).
ZMQ_EXPORT size_t zmq_msg_size (struct zmq_msg_t *msg);

////////////////////////////////////////////////////////////////////////////////
//  0MQ infrastructure (a.k.a. context) initialisation & termination.
////////////////////////////////////////////////////////////////////////////////

//  Flag specifying that the sockets within this context should be pollable.
//  This may be a little less efficient that raw non-pollable sockets.
#define ZMQ_POLL 1

//  Initialise 0MQ context. 'app_threads' specifies maximal number
//  of application threads that can own open sockets at the same time.
//  'io_threads' specifies the size of thread pool to handle I/O operations.
//  'flags' argument is a bitmap composed of the flags defined above.
//
//  Errors: EINVAL - one of the arguments is less than zero or there are no
//                   threads declared at all.
ZMQ_EXPORT void *zmq_init (int app_threads, int io_threads, int flags);

//  Deinitialise 0MQ context. If there are still open sockets, actual
//  deinitialisation of the context is delayed till all the sockets are closed.
ZMQ_EXPORT int zmq_term (void *context);

////////////////////////////////////////////////////////////////////////////////
//  0MQ socket definition.
////////////////////////////////////////////////////////////////////////////////

//  Creating a 0MQ socket.
//  **********************

//  Socket to communicate with a single peer. Allows for a singe connect or a
//  single accept. There's no message routing or message filtering involved.
#define ZMQ_P2P 0

//  Socket to distribute data. Recv fuction is not implemented for this socket
//  type. Messages are distributed in fanout fashion to all the peers.
#define ZMQ_PUB 1

//  Socket to subscribe for data. Send function is not implemented for this
//  socket type. However, subscribe function can be used to modify the
//  message filter (see ZMQ_SUBSCRIBE socket option).
#define ZMQ_SUB 2

//  Socket to send requests and receive replies. Requests are
//  load-balanced among all the peers. This socket type allows
//  only an alternated sequence of send's and recv's
#define ZMQ_REQ 3

//  Socket to receive requests and send replies. This socket type allows
//  only an alternated sequence of recv's and send's. Each send is routed to
//  the peer that issued the last received request.
#define ZMQ_REP 4

//  Open a socket. 'type' is one of the socket types defined above.
//
//  Errors: EINVAL - invalid socket type.
//          EMTHREAD - the number of application threads entitled to hold open
//                     sockets at the same time was exceeded.
ZMQ_EXPORT void *zmq_socket (void *context, int type);

//  Destroying the socket.
//  **********************

//  Close the socket.
ZMQ_EXPORT int zmq_close (void *s);

//  Manipulating socket options.
//  ****************************

//  Available socket options, their types and default values.

//  High watermark for the message pipes associated with the socket. The water
//  mark cannot be exceeded. If the messages don't fit into the pipe emergency
//  mechanisms of the particular socket type are used (block, drop etc.) If HWM
//  is set to zero, there are no limits for the content of the pipe.
//  Type: int64_t  Unit: bytes  Default: 0
#define ZMQ_HWM 1

//  Low watermark makes sense only if high watermark is defined (is non-zero).
//  When the emergency state is reached when messages overflow the pipe, the
//  emergency lasts till the size of the pipe decreases to low watermark.
//  At that point normal state is resumed.
//  Type: int64_t  Unit: bytes  Default: 0
#define ZMQ_LWM 2

//  Swap allows the pipe to exceed high watermark. However, the data are written
//  to the disk rather than held in the memory. While the high watermark is not
//  exceeded there is no disk activity involved though. The value of the option
//  defines maximal size of the swap file.
//  Type: int64_t  Unit: bytes  Default: 0
#define ZMQ_SWAP 3

//  Affinity defines which threads in the thread pool will be used to handle
//  newly created sockets. This way you can dedicate some of the threads (CPUs)
//  to a specific work. Value of 0 means no affinity, work is distributed
//  fairly among the threads in the thread pool. For non-zero values, the lowest
//  bit corresponds to the thread 1, second lowest bit to the thread 2 etc.
//  Thus, value of 3 means that from now on newly created sockets will handle
//  I/O activity exclusively using threads no. 1 and 2.
//  Type: int64_t  Unit: N/A (bitmap)  Default: 0
#define ZMQ_AFFINITY 4

//  Identity of the socket. Identity is important when restarting applications.
//  If the socket has no identity, each run of the application is completely
//  separated from other runs. However, with identity application reconnects to
//  existing infrastructure left by the previous run. Thus it may receive
//  messages that were sent in the meantime, it shares pipe limits with the
//  previous run etc.
//  Type: string  Unit: N/A  Default: NULL
#define ZMQ_IDENTITY 5

//  Applicable only to 'sub' socket type. Eastablishes new message filter.
//  When 'sub' socket is created all the incoming messages are filtered out.
//  This option allows you to subscribe for all messages ("*"), messages with
//  specific topic ("x.y.z") and/or messages with specific topic prefix
//  ("x.y.*"). Topic is one-byte-size-prefixed string located at
//  the very beginning of the message. Multiple filters can be attached to
//  a single 'sub' socket. In that case message passes if it matches at least
//  one of the filters.
//  Type: string  Unit: N/A  Default: N/A
#define ZMQ_SUBSCRIBE 6

//  Applicable only to 'sub' socket type. Removes existing message filter.
//  The filter specified must match the string passed to ZMQ_SUBSCRIBE options
//  exactly. If there were several instances of the same filter created,
//  this options removes only one of them, leaving the rest in place
//  and functional.
//  Type: string  Unit: N/A  Default: N/A
#define ZMQ_UNSUBSCRIBE 7

//  This option applies only to multicast transports (pgm & udp). It specifies
//  maximal outgoing data rate that an individual sender socket can send.
//  Type: uint64_t  Unit: kilobits/second  Default: 100
#define ZMQ_RATE 8

//  This option applies only to multicast transports (pgm & udp). It specifies
//  how long can the receiver socket survive when the sender is inaccessible.
//  Keep in mind that large recovery intervals at high data rates result in
//  very large recovery buffers, meaning that you can easily overload your box
//  by setting say 1 minute recovery interval at 1Gb/s rate (requires
//  7GB in-memory buffer).
//  Type: uint64_t Unit: seconds Default: 10 
#define ZMQ_RECOVERY_IVL 9

//  This option applies only to multicast transports (pgm & udp). Value of 1
//  means that the mutlicast packets can be received on the box they were sent
//  from. Setting the value to 0 disables the loopback functionality which
//  can have negative impact on the performance. if possible, disable
//  the loopback in production environments.
//  Type: uint64_t Unit: N/A (boolean value) Default: 1
#define ZMQ_MCAST_LOOP 10

//  Sets an option on the socket. 'option' argument specifies the option (see
//  the option list above). 'optval' is a pointer to the value to set,
//  'optvallen' is the size of the value in bytes.
//
//  Errors: EINVAL - unknown option, a value with incorrect length
//                   or invalid value.
ZMQ_EXPORT int zmq_setsockopt (void *s, int option, const void *optval,
    size_t optvallen); 

//  Creating connections.
//  *********************

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

//  Bind the socket to a particular address.
//
//  Errors: EPROTONOSUPPORT - unsupported protocol.
//          ENOCOMPATPROTO - protocol is not compatible with the socket type.
ZMQ_EXPORT int zmq_bind (void *s, const char *addr);

//  Connect the socket to a particular address.
//
//  Errors: EPROTONOSUPPORT - unsupported protocol.
//          ENOCOMPATPROTO - protocol is not compatible with the socket type.
ZMQ_EXPORT int zmq_connect (void *s, const char *addr);

//  Sending and receiving messages.
//  *******************************

//  The flag specifying that the operation should be performed in
//  non-blocking mode. I.e. if it cannot be processed immediately,
//  error should be returned with errno set to EAGAIN.
#define ZMQ_NOBLOCK 1

//  The flag specifying that zmq_send should not flush the message downstream
//  immediately. Instead, it should batch ZMQ_NOFLUSH messages and send them
//  downstream only if zmq_flush is invoked. This is an optimisation for cases
//  where several messages are sent in a single business transaction. However,
//  the effect is measurable only in extremely high-perf scenarios
//  (million messages a second or so). If that's not your case, use standard
//  flushing send instead.
#define ZMQ_NOFLUSH 2

//  Send the message 'msg' to the socket 's'. 'flags' argument can be
//  combination the flags described above.
//
//  Errors: EAGAIN - message cannot be sent at the moment (applies only to
//                   non-blocking send).
//          ENOTSUP - function isn't supported by particular socket type.
//          EFSM - function cannot be called at the moment. 
ZMQ_EXPORT int zmq_send (void *s, struct zmq_msg_t *msg, int flags);

//  Flush the messages that were send using ZMQ_NOFLUSH flag down the stream.
//
//  Errors: ENOTSUP - function isn't supported by particular socket type.
//          EFSM - function cannot be called at the moment. 
ZMQ_EXPORT int zmq_flush (void *s);

//  Send a message from the socket 's'. 'flags' argument can be combination
//  of the flags described above.
//
//  Errors: EAGAIN - message cannot be received at the moment (applies only to
//                   non-blocking receive).
//          ENOTSUP - function isn't supported by particular socket type.
//          EFSM - function cannot be called at the moment. 
ZMQ_EXPORT int zmq_recv (void *s, struct zmq_msg_t *msg, int flags);

////////////////////////////////////////////////////////////////////////////////
//  Helper functions.
////////////////////////////////////////////////////////////////////////////////

//  Helper functions used by perf tests so that they don't have to care
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
