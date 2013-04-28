/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include "platform.hpp"
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include <string.h>
#include <new>

#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "v1_encoder.hpp"
#include "v1_decoder.hpp"
#include "v2_encoder.hpp"
#include "v2_decoder.hpp"
#include "raw_decoder.hpp"
#include "raw_encoder.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::stream_engine_t::stream_engine_t (fd_t fd_, const options_t &options_, const std::string &endpoint_) :
    s (fd_),
    inpos (NULL),
    insize (0),
    decoder (NULL),
    outpos (NULL),
    outsize (0),
    encoder (NULL),
    handshaking (true),
    greeting_size (v2_greeting_size),
    greeting_bytes_read (0),
    session (NULL),
    options (options_),
    endpoint (endpoint_),
    plugged (false),
    terminating (false),
    read_msg (&stream_engine_t::read_identity),
    write_msg (&stream_engine_t::write_identity),
    io_error (false),
    congested (false),
    subscription_required (false),
    output_paused (false),
    ready_command_received (false),
    socket (NULL)
{
    int rc = tx_msg.init ();
    errno_assert (rc == 0);

    //  Put the socket into non-blocking mode.
    unblock_socket (s);
    //  Set the socket buffer limits for the underlying socket.
    if (options.sndbuf) {
        rc = setsockopt (s, SOL_SOCKET, SO_SNDBUF,
            (char*) &options.sndbuf, sizeof (int));
#ifdef ZMQ_HAVE_WINDOWS
		wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif
    }
    if (options.rcvbuf) {
        rc = setsockopt (s, SOL_SOCKET, SO_RCVBUF,
            (char*) &options.rcvbuf, sizeof (int));
#ifdef ZMQ_HAVE_WINDOWS
		wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif
    }

#ifdef SO_NOSIGPIPE
    //  Make sure that SIGPIPE signal is not generated when writing to a
    //  connection that was already closed by the peer.
    int set = 1;
    rc = setsockopt (s, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof (int));
    errno_assert (rc == 0);
#endif
}

zmq::stream_engine_t::~stream_engine_t ()
{
    zmq_assert (!plugged);

    if (s != retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (s);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = close (s);
        errno_assert (rc == 0);
#endif
        s = retired_fd;
    }

    int rc = tx_msg.close ();
    errno_assert (rc == 0);

    if (encoder != NULL)
        delete encoder;
    if (decoder != NULL)
        delete decoder;
}

void zmq::stream_engine_t::plug (io_thread_t *io_thread_,
    session_base_t *session_)
{
    zmq_assert (!plugged);
    plugged = true;

    //  Connect to session object.
    zmq_assert (!session);
    zmq_assert (session_);
    session = session_;
    socket = session-> get_socket ();

    //  Connect to I/O threads poller object.
    io_object_t::plug (io_thread_);
    handle = add_fd (s);
    io_error = false;

    if (options.raw_sock) {
        // no handshaking for raw sock, instantiate raw encoder and decoders
        encoder = new (std::nothrow) raw_encoder_t (out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) raw_decoder_t (in_batch_size);
        alloc_assert (decoder);

        // disable handshaking for raw socket
        handshaking = false;

        read_msg = &stream_engine_t::pull_msg_from_session;
        write_msg = &stream_engine_t::push_msg_to_session;
    }
    else {
        //  Send the 'length' and 'flags' fields of the identity message.
        //  The 'length' field is encoded in the long format.
        outpos = greeting_send;
        outpos [outsize++] = 0xff;
        put_uint64 (&outpos [outsize], options.identity_size + 1);
        outsize += 8;
        outpos [outsize++] = 0x7f;
    }

    set_pollin (handle);
    set_pollout (handle);
    //  Flush all the data that may have been already received downstream.
    in_event ();
}

void zmq::stream_engine_t::unplug ()
{
    zmq_assert (plugged);
    plugged = false;

    //  Cancel all fd subscriptions.
    if (!io_error)
        rm_fd (handle);

    //  Disconnect from I/O threads poller object.
    io_object_t::unplug ();

    session = NULL;
}

void zmq::stream_engine_t::terminate ()
{
    if (!terminating && encoder && encoder->has_data ()) {
        //  Give io_thread a chance to send in the buffer
        terminating = true;
        return;
    }
    unplug ();
    delete this;
}

void zmq::stream_engine_t::in_event ()
{
    assert (!io_error);

    //  If still handshaking, receive and process the greeting message.
    if (unlikely (handshaking))
        if (!handshake ())
            return;

    zmq_assert (decoder);

    //  If there has been an I/O error, stop polling.
    if (congested) {
        rm_fd (handle);
        io_error = true;
        return;
    }

    //  If there's no data to process in the buffer...
    if (!insize) {

        //  Retrieve the buffer and read as much data as possible.
        //  Note that buffer can be arbitrarily large. However, we assume
        //  the underlying TCP layer has fixed buffer size and thus the
        //  number of bytes read will be always limited.
        decoder->get_buffer (&inpos, &insize);
        const int bytes_read = read (inpos, insize);

        //  Check whether the peer has closed the connection.
        if (bytes_read == -1) {
            error ();
            return;
        }

        //  Adjust input size
        insize = static_cast <size_t> (bytes_read);
    }

    int rc = 0;
    size_t processed = 0;

    while (insize > 0) {
        rc = decoder->decode (inpos, insize, processed);
        zmq_assert (processed <= insize);
        inpos += processed;
        insize -= processed;
        if (rc == 0 || rc == -1)
            break;
        rc = (this->*write_msg) (decoder->msg ());
        if (rc == -1)
            break;
    }

    //  Tear down the connection if we have failed to decode input data
    //  or the session has rejected the message.
    if (rc == -1) {
        if (errno != EAGAIN) {
            error ();
            return;
        }
        congested = true;
        reset_pollin (handle);
    }

    session->flush ();
}

void zmq::stream_engine_t::out_event ()
{
    zmq_assert (!io_error);

    //  If write buffer is empty, try to read new data from the encoder.
    if (!outsize) {

        //  Even when we stop polling as soon as there is no
        //  data to send, the poller may invoke out_event one
        //  more time due to 'speculative write' optimisation.
        if (unlikely (encoder == NULL)) {
            zmq_assert (handshaking);
            return;
        }

        outpos = NULL;
        outsize = encoder->encode (&outpos, 0);

        while (outsize < out_batch_size) {
            if ((this->*read_msg) (&tx_msg) == -1)
                break;
            encoder->load_msg (&tx_msg);
            unsigned char *bufptr = outpos + outsize;
            size_t n = encoder->encode (&bufptr, out_batch_size - outsize);
            zmq_assert (n > 0);
            if (outpos == NULL)
                outpos = bufptr;
            outsize += n;
        }

        //  If there is no data to send, stop polling for output.
        if (outsize == 0) {
            reset_pollout (handle);
            return;
        }
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket. Note that amount of data to write can be
    //  arbitrarily large. However, we assume that underlying TCP layer has
    //  limited transmission buffer and thus the actual number of bytes
    //  written should be reasonably modest.
    int nbytes = write (outpos, outsize);

    //  IO error has occurred. We stop waiting for output events.
    //  The engine is not terminated until we detect input error;
    //  this is necessary to prevent losing incoming messages.
    if (nbytes == -1) {
        reset_pollout (handle);
        if (unlikely (terminating))
            terminate ();
        return;
    }

    outpos += nbytes;
    outsize -= nbytes;

    //  If we are still handshaking and there are no data
    //  to send, stop polling for output.
    if (unlikely (handshaking))
        if (outsize == 0)
            reset_pollout (handle);

    if (unlikely (terminating))
        if (outsize == 0)
            terminate ();
}

void zmq::stream_engine_t::activate_out ()
{
    if (unlikely (io_error))
        return;

    set_pollout (handle);

    //  Speculative write: The assumption is that at the moment new message
    //  was sent by the user the socket is probably available for writing.
    //  Thus we try to write the data to socket avoiding polling for POLLOUT.
    //  Consequently, the latency should be better in request/reply scenarios.
    out_event ();
}

void zmq::stream_engine_t::activate_in ()
{
    zmq_assert (congested);
    zmq_assert (session != NULL);
    zmq_assert (decoder != NULL);

    int rc = (this->*write_msg) (decoder->msg ());
    if (rc == -1) {
        if (errno == EAGAIN)
            session->flush ();
        else
            error ();
        return;
    }

    while (insize > 0) {
        size_t processed = 0;
        rc = decoder->decode (inpos, insize, processed);
        zmq_assert (processed <= insize);
        inpos += processed;
        insize -= processed;
        if (rc == 0 || rc == -1)
            break;
        rc = (this->*write_msg) (decoder->msg ());
        if (rc == -1)
            break;
    }

    if (rc == -1 && errno == EAGAIN)
        session->flush ();
    else
    if (rc == -1 || io_error)
        error ();
    else {
        congested = false;
        set_pollin (handle);
        session->flush ();

        //  Speculative read.
        in_event ();
    }
}

bool zmq::stream_engine_t::handshake ()
{
    zmq_assert (handshaking);
    zmq_assert (greeting_bytes_read < greeting_size);

    //  Receive the greeting.
    while (greeting_bytes_read < greeting_size) {
        const int n = read (greeting_recv + greeting_bytes_read,
                            greeting_size - greeting_bytes_read);
        if (n == -1) {
            error ();
            return false;
        }
        if (n == 0)
            return false;

        greeting_bytes_read += n;

        //  We have received at least one byte from the peer.
        //  If the first byte is not 0xff, we know that the
        //  peer is using unversioned protocol.
        if (greeting_recv [0] != 0xff)
            break;

        if (greeting_bytes_read < signature_size)
            continue;

        //  Inspect the right-most bit of the 10th byte (which coincides
        //  with the 'flags' field if a regular message was sent).
        //  Zero indicates this is a header of identity message
        //  (i.e. the peer is using the unversioned protocol).
        if (!(greeting_recv [9] & 0x01))
            break;

        //  The peer is using versioned protocol.
        //  Send the major version number.
        if (outpos + outsize == greeting_send + signature_size) {
            if (outsize == 0)
                set_pollout (handle);
            outpos [outsize++] = 3;     //  Major version number
        }

        if (greeting_bytes_read > signature_size) {
            if (outpos + outsize == greeting_send + signature_size + 1) {
                if (outsize == 0)
                    set_pollout (handle);

                //  Use ZMTP/2.0 to talk to older peers.
                if (greeting_recv [10] == ZMTP_1_0
                ||  greeting_recv [10] == ZMTP_2_0)
                    outpos [outsize++] = options.type;
                else {
                    outpos [outsize++] = 0; //  Minor version number
                    memset (outpos + outsize, 0, 20);
                    memcpy (outpos + outsize, "NULL", 4);
                    outsize += 20;
                    memset (outpos + outsize, 0, 32);
                    outsize += 32;
                    greeting_size = v3_greeting_size;
                }
            }
        }
    }

    //  Position of the revision field in the greeting.
    const size_t revision_pos = 10;

    //  Is the peer using ZMTP/1.0 with no revision number?
    //  If so, we send and receive rest of identity message
    if (greeting_recv [0] != 0xff || !(greeting_recv [9] & 0x01)) {
        encoder = new (std::nothrow) v1_encoder_t (out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) v1_decoder_t (in_batch_size, options.maxmsgsize);
        alloc_assert (decoder);

        //  We have already sent the message header.
        //  Since there is no way to tell the encoder to
        //  skip the message header, we simply throw that
        //  header data away.
        const size_t header_size = options.identity_size + 1 >= 255 ? 10 : 2;
        unsigned char tmp [10], *bufferp = tmp;
        size_t buffer_size = encoder->encode (&bufferp, header_size);
        zmq_assert (buffer_size == header_size);

        //  Make sure the decoder sees the data we have already received.
        inpos = greeting_recv;
        insize = greeting_bytes_read;

        //  To allow for interoperability with peers that do not forward
        //  their subscriptions, we inject a phony subscription
        //  message into the incomming message stream.
        if (options.type == ZMQ_PUB || options.type == ZMQ_XPUB)
            subscription_required = true;
    }
    else
    if (greeting_recv [revision_pos] == ZMTP_1_0) {
        encoder = new (std::nothrow) v1_encoder_t (
            out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) v1_decoder_t (
            in_batch_size, options.maxmsgsize);
        alloc_assert (decoder);
    }
    else
    if (greeting_recv [revision_pos] == ZMTP_2_0) {
        encoder = new (std::nothrow) v2_encoder_t (out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) v2_decoder_t (
            in_batch_size, options.maxmsgsize);
        alloc_assert (decoder);
    }
    else {
        encoder = new (std::nothrow) v2_encoder_t (out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) v2_decoder_t (
            in_batch_size, options.maxmsgsize);
        alloc_assert (decoder);

        if (memcmp (greeting_recv + 12, "NULL\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20) == 0) {
            read_msg = &stream_engine_t::send_ready_command;
            write_msg = &stream_engine_t::receive_ready_command;
        }
        else {
            error ();
            return false;
        }
    }

    // Start polling for output if necessary.
    if (outsize == 0)
        set_pollout (handle);

    //  Handshaking was successful.
    //  Switch into the normal message flow.
    handshaking = false;

    return true;
}

int zmq::stream_engine_t::read_identity (msg_t *msg_)
{
    int rc = msg_->init_size (options.identity_size);
    errno_assert (rc == 0);
    if (options.identity_size > 0)
        memcpy (msg_->data (), options.identity, options.identity_size);
    read_msg = &stream_engine_t::pull_msg_from_session;
    return 0;
}

int zmq::stream_engine_t::write_identity (msg_t *msg_)
{
    if (options.recv_identity) {
        msg_->set_flags (msg_t::identity);
        int rc = session->push_msg (msg_);
        errno_assert (rc == 0);
    }
    else {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    if (subscription_required)
        write_msg = &stream_engine_t::write_subscription_msg;
    else
        write_msg = &stream_engine_t::push_msg_to_session;

    return 0;
}

int zmq::stream_engine_t::send_ready_command (msg_t *msg_)
{
    unsigned char * const command_buffer = (unsigned char *) malloc (512);
    alloc_assert (command_buffer);

    unsigned char *ptr = command_buffer;

    //  Add mechanism string
    memcpy (ptr, "READY   ", 8);
    ptr += 8;

    //  Add socket type property
    const char *socket_type = socket_type_string (options.type);
    ptr += add_property (ptr, "Socket-Type", socket_type, strlen (socket_type));

    //  Add identity property
    if (options.type == ZMQ_REQ
    ||  options.type == ZMQ_DEALER
    ||  options.type == ZMQ_ROUTER) {
        ptr += add_property (ptr, "Identity",
            options.identity, options.identity_size);
    }

    const size_t command_size = ptr - command_buffer;
    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);
    memcpy (msg_->data (), command_buffer, command_size);
    free (command_buffer);

    if (ready_command_received)
        read_msg = &stream_engine_t::pull_msg_from_session;
    else
        read_msg = &stream_engine_t::wait;

    return 0;
}

int zmq::stream_engine_t::receive_ready_command (msg_t *msg_)
{
    const unsigned char * const command_buffer =
        static_cast <unsigned char *> (msg_->data ());
    const size_t command_size = msg_->size ();

    const unsigned char *ptr = command_buffer;
    size_t bytes_left = command_size;

    if (bytes_left < 8 || memcmp(ptr, "READY   ", 8)) {
        errno = EPROTO;
        return -1;
    }

    ptr += 8;
    bytes_left -= 8;

    //  Parse the property list
    while (bytes_left > 1) {
        const size_t name_length = static_cast <size_t> (*ptr);
        ptr += 1;
        bytes_left -= 1;

        if (bytes_left < name_length)
            break;
        const std::string name = std::string((const char *) ptr, name_length);
        ptr += name_length;
        bytes_left -= name_length;

        if (bytes_left < 4)
            break;
        const size_t value_length = static_cast <size_t> (get_uint32 (ptr));
        ptr += 4;
        bytes_left -= 4;

        if (bytes_left < value_length)
            break;
        const unsigned char * const value = ptr;
        ptr += value_length;
        bytes_left -= value_length;

        if (name == "Socket-Type") {
            //  Implement socket type checking
        }
        else
        if (name == "Identity") {
            if (options.recv_identity) {
                msg_t identity;
                int rc = identity.init_size (value_length);
                errno_assert (rc == 0);
                memcpy (identity.data (), value, value_length);
                identity.set_flags (msg_t::identity);
                rc = session->push_msg (&identity);
                errno_assert (rc == 0);
            }
        }
    }

    if (bytes_left > 0) {
        errno = EPROTO;
        return -1;
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init ();
    errno_assert (rc == 0);

    write_msg = &stream_engine_t::push_msg_to_session;

    ready_command_received = true;
    if (output_paused) {
        activate_out ();
        output_paused = false;
    }

    return 0;
}

int zmq::stream_engine_t::wait (msg_t *msg_)
{
    if (ready_command_received) {
        read_msg = &stream_engine_t::pull_msg_from_session;
        return pull_msg_from_session (msg_);
    }
    else {
        output_paused = true;
        errno = EAGAIN;
        return -1;
    }
}

int zmq::stream_engine_t::pull_msg_from_session (msg_t *msg_)
{
    return session->pull_msg (msg_);
}

int zmq::stream_engine_t::push_msg_to_session (msg_t *msg_)
{
    return session->push_msg (msg_);
}

int zmq::stream_engine_t::write_subscription_msg (msg_t *msg_)
{
    msg_t subscription;

    //  Inject the subscription message, so that also
    //  ZMQ 2.x peers receive published messages.
    int rc = subscription.init_size (1);
    errno_assert (rc == 0);
    *(unsigned char*) subscription.data () = 1;
    rc = session->push_msg (&subscription);
    if (rc == -1)
       return -1;

    write_msg = &stream_engine_t::push_msg_to_session;
    return push_msg_to_session (msg_);
}

size_t zmq::stream_engine_t::add_property (unsigned char *ptr,
    const char *name, const void *value, size_t value_len)
{
    const size_t name_len = strlen (name);
    zmq_assert (name_len <= 255);
    *ptr++ = static_cast <unsigned char> (name_len);
    memcpy (ptr, name, name_len);
    ptr += name_len;
    zmq_assert (value_len <= (2^31) - 1);
    put_uint32 (ptr, static_cast <uint32_t> (value_len));
    ptr += 4;
    memcpy (ptr, value, value_len);

    return 1 + name_len + 4 + value_len;
}

const char *zmq::stream_engine_t::socket_type_string (int socket_type) {
    const char *names [] = {"PAIR", "PUB", "SUB", "REQ", "REP", "DEALER",
                            "ROUTER", "PULL", "PUSH", "XPUB", "XSUB"};
    zmq_assert (socket_type >= 0 && socket_type <= 10);
    return names [socket_type];
}

void zmq::stream_engine_t::error ()
{
    zmq_assert (session);
    socket->event_disconnected (endpoint, s);
    session->flush ();
    session->detach ();
    unplug ();
    delete this;
}

int zmq::stream_engine_t::write (const void *data_, size_t size_)
{
#ifdef ZMQ_HAVE_WINDOWS

    int nbytes = send (s, (char*) data_, (int) size_, 0);

    //  If not a single byte can be written to the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative write).
    if (nbytes == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;
		
    //  Signalise peer failure.
    if (nbytes == SOCKET_ERROR && (
          WSAGetLastError () == WSAENETDOWN ||
          WSAGetLastError () == WSAENETRESET ||
          WSAGetLastError () == WSAEHOSTUNREACH ||
          WSAGetLastError () == WSAECONNABORTED ||
          WSAGetLastError () == WSAETIMEDOUT ||
          WSAGetLastError () == WSAECONNRESET))
        return -1;

    wsa_assert (nbytes != SOCKET_ERROR);
    return nbytes;

#else

    ssize_t nbytes = send (s, data_, size_, 0);

    //  Several errors are OK. When speculative write is being done we may not
    //  be able to write a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EACCES
                   && errno != EBADF
                   && errno != EDESTADDRREQ
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != EISCONN
                   && errno != EMSGSIZE
                   && errno != ENOMEM
                   && errno != ENOTSOCK
                   && errno != EOPNOTSUPP);
        return -1;
    }

    return static_cast <int> (nbytes);

#endif
}

int zmq::stream_engine_t::read (void *data_, size_t size_)
{
#ifdef ZMQ_HAVE_WINDOWS

    int nbytes = recv (s, (char*) data_, (int) size_, 0);

    //  If not a single byte can be read from the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative read).
    if (nbytes == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;

    //  Connection failure.
    if (nbytes == SOCKET_ERROR && (
          WSAGetLastError () == WSAENETDOWN ||
          WSAGetLastError () == WSAENETRESET ||
          WSAGetLastError () == WSAECONNABORTED ||
          WSAGetLastError () == WSAETIMEDOUT ||
          WSAGetLastError () == WSAECONNRESET ||
          WSAGetLastError () == WSAECONNREFUSED ||
          WSAGetLastError () == WSAENOTCONN))
        return -1;

    wsa_assert (nbytes != SOCKET_ERROR);

    //  Orderly shutdown by the other peer.
    if (nbytes == 0)
        return -1; 

    return nbytes;

#else

    ssize_t nbytes = recv (s, data_, size_, 0);

    //  Several errors are OK. When speculative read is being done we may not
    //  be able to read a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EBADF
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != ENOMEM
                   && errno != ENOTSOCK);
        return -1;
    }

    //  Orderly shutdown by the peer.
    if (nbytes == 0)
        return -1;

    return static_cast <int> (nbytes);

#endif
}
