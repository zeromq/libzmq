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

#include "precompiled.hpp"
#include "macros.hpp"

#include <limits.h>
#include <string.h>

#ifndef ZMQ_HAVE_WINDOWS
#include <unistd.h>
#endif

#include <new>
#include <sstream>

#include "stream_engine.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "v1_encoder.hpp"
#include "v1_decoder.hpp"
#include "v2_encoder.hpp"
#include "v2_decoder.hpp"
#include "null_mechanism.hpp"
#include "plain_client.hpp"
#include "plain_server.hpp"
#include "gssapi_client.hpp"
#include "gssapi_server.hpp"
#include "curve_client.hpp"
#include "curve_server.hpp"
#include "raw_decoder.hpp"
#include "raw_encoder.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "likely.hpp"
#include "wire.hpp"

static std::string get_peer_address (zmq::fd_t s_)
{
    std::string peer_address;

    const int family = zmq::get_peer_ip_address (s_, peer_address);
    if (family == 0)
        peer_address.clear ();
#if defined ZMQ_HAVE_SO_PEERCRED
    else if (family == PF_UNIX) {
        struct ucred cred;
        socklen_t size = sizeof (cred);
        if (!getsockopt (s_, SOL_SOCKET, SO_PEERCRED, &cred, &size)) {
            std::ostringstream buf;
            buf << ":" << cred.uid << ":" << cred.gid << ":" << cred.pid;
            peer_address += buf.str ();
        }
    }
#elif defined ZMQ_HAVE_LOCAL_PEERCRED
    else if (family == PF_UNIX) {
        struct xucred cred;
        socklen_t size = sizeof (cred);
        if (!getsockopt (_s, 0, LOCAL_PEERCRED, &cred, &size)
            && cred.cr_version == XUCRED_VERSION) {
            std::ostringstream buf;
            buf << ":" << cred.cr_uid << ":";
            if (cred.cr_ngroups > 0)
                buf << cred.cr_groups[0];
            buf << ":";
            _peer_address += buf.str ();
        }
    }
#endif

    return peer_address;
}


zmq::stream_engine_t::stream_engine_t (
  fd_t fd_,
  const options_t &options_,
  const endpoint_uri_pair_t &endpoint_uri_pair_) :
    _s (fd_),
    _handle (static_cast<handle_t> (NULL)),
    _inpos (NULL),
    _insize (0),
    _decoder (NULL),
    _outpos (NULL),
    _outsize (0),
    _encoder (NULL),
    _metadata (NULL),
    _handshaking (true),
    _greeting_size (v2_greeting_size),
    _greeting_bytes_read (0),
    _session (NULL),
    _options (options_),
    _endpoint_uri_pair (endpoint_uri_pair_),
    _plugged (false),
    _next_msg (&stream_engine_t::routing_id_msg),
    _process_msg (&stream_engine_t::process_routing_id_msg),
    _io_error (false),
    _subscription_required (false),
    _mechanism (NULL),
    _input_stopped (false),
    _output_stopped (false),
    _has_handshake_timer (false),
    _has_ttl_timer (false),
    _has_timeout_timer (false),
    _has_heartbeat_timer (false),
    _heartbeat_timeout (0),
    _socket (NULL),
    _peer_address (get_peer_address (_s))
{
    int rc = _tx_msg.init ();
    errno_assert (rc == 0);
    rc = _pong_msg.init ();
    errno_assert (rc == 0);

    //  Put the socket into non-blocking mode.
    unblock_socket (_s);


    if (_options.heartbeat_interval > 0) {
        _heartbeat_timeout = _options.heartbeat_timeout;
        if (_heartbeat_timeout == -1)
            _heartbeat_timeout = _options.heartbeat_interval;
    }
}

zmq::stream_engine_t::~stream_engine_t ()
{
    zmq_assert (!_plugged);

    if (_s != retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (_s);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = close (_s);
#if defined(__FreeBSD_kernel__) || defined(__FreeBSD__)
        // FreeBSD may return ECONNRESET on close() under load but this is not
        // an error.
        if (rc == -1 && errno == ECONNRESET)
            rc = 0;
#endif
        errno_assert (rc == 0);
#endif
        _s = retired_fd;
    }

    int rc = _tx_msg.close ();
    errno_assert (rc == 0);

    //  Drop reference to metadata and destroy it if we are
    //  the only user.
    if (_metadata != NULL) {
        if (_metadata->drop_ref ()) {
            LIBZMQ_DELETE (_metadata);
        }
    }

    LIBZMQ_DELETE (_encoder);
    LIBZMQ_DELETE (_decoder);
    LIBZMQ_DELETE (_mechanism);
}

void zmq::stream_engine_t::plug (io_thread_t *io_thread_,
                                 session_base_t *session_)
{
    zmq_assert (!_plugged);
    _plugged = true;

    //  Connect to session object.
    zmq_assert (!_session);
    zmq_assert (session_);
    _session = session_;
    _socket = _session->get_socket ();

    //  Connect to I/O threads poller object.
    io_object_t::plug (io_thread_);
    _handle = add_fd (_s);
    _io_error = false;

    if (_options.raw_socket) {
        // no handshaking for raw sock, instantiate raw encoder and decoders
        _encoder = new (std::nothrow) raw_encoder_t (out_batch_size);
        alloc_assert (_encoder);

        _decoder = new (std::nothrow) raw_decoder_t (in_batch_size);
        alloc_assert (_decoder);

        // disable handshaking for raw socket
        _handshaking = false;

        _next_msg = &stream_engine_t::pull_msg_from_session;
        _process_msg = &stream_engine_t::push_raw_msg_to_session;

        properties_t properties;
        if (init_properties (properties)) {
            //  Compile metadata.
            zmq_assert (_metadata == NULL);
            _metadata = new (std::nothrow) metadata_t (properties);
            alloc_assert (_metadata);
        }

        if (_options.raw_notify) {
            //  For raw sockets, send an initial 0-length message to the
            // application so that it knows a peer has connected.
            msg_t connector;
            connector.init ();
            push_raw_msg_to_session (&connector);
            connector.close ();
            _session->flush ();
        }
    } else {
        // start optional timer, to prevent handshake hanging on no input
        set_handshake_timer ();

        //  Send the 'length' and 'flags' fields of the routing id message.
        //  The 'length' field is encoded in the long format.
        _outpos = _greeting_send;
        _outpos[_outsize++] = UCHAR_MAX;
        put_uint64 (&_outpos[_outsize], _options.routing_id_size + 1);
        _outsize += 8;
        _outpos[_outsize++] = 0x7f;
    }

    set_pollin (_handle);
    set_pollout (_handle);
    //  Flush all the data that may have been already received downstream.
    in_event ();
}

void zmq::stream_engine_t::unplug ()
{
    zmq_assert (_plugged);
    _plugged = false;

    //  Cancel all timers.
    if (_has_handshake_timer) {
        cancel_timer (handshake_timer_id);
        _has_handshake_timer = false;
    }

    if (_has_ttl_timer) {
        cancel_timer (heartbeat_ttl_timer_id);
        _has_ttl_timer = false;
    }

    if (_has_timeout_timer) {
        cancel_timer (heartbeat_timeout_timer_id);
        _has_timeout_timer = false;
    }

    if (_has_heartbeat_timer) {
        cancel_timer (heartbeat_ivl_timer_id);
        _has_heartbeat_timer = false;
    }
    //  Cancel all fd subscriptions.
    if (!_io_error)
        rm_fd (_handle);

    //  Disconnect from I/O threads poller object.
    io_object_t::unplug ();

    _session = NULL;
}

void zmq::stream_engine_t::terminate ()
{
    unplug ();
    delete this;
}

void zmq::stream_engine_t::in_event ()
{
    zmq_assert (!_io_error);

    //  If still handshaking, receive and process the greeting message.
    if (unlikely (_handshaking))
        if (!handshake ())
            return;

    zmq_assert (_decoder);

    //  If there has been an I/O error, stop polling.
    if (_input_stopped) {
        rm_fd (_handle);
        _io_error = true;
        return;
    }

    //  If there's no data to process in the buffer...
    if (!_insize) {
        //  Retrieve the buffer and read as much data as possible.
        //  Note that buffer can be arbitrarily large. However, we assume
        //  the underlying TCP layer has fixed buffer size and thus the
        //  number of bytes read will be always limited.
        size_t bufsize = 0;
        _decoder->get_buffer (&_inpos, &bufsize);

        const int rc = tcp_read (_s, _inpos, bufsize);

        if (rc == 0) {
            // connection closed by peer
            errno = EPIPE;
            error (connection_error);
            return;
        }
        if (rc == -1) {
            if (errno != EAGAIN)
                error (connection_error);
            return;
        }

        //  Adjust input size
        _insize = static_cast<size_t> (rc);
        // Adjust buffer size to received bytes
        _decoder->resize_buffer (_insize);
    }

    int rc = 0;
    size_t processed = 0;

    while (_insize > 0) {
        rc = _decoder->decode (_inpos, _insize, processed);
        zmq_assert (processed <= _insize);
        _inpos += processed;
        _insize -= processed;
        if (rc == 0 || rc == -1)
            break;
        rc = (this->*_process_msg) (_decoder->msg ());
        if (rc == -1)
            break;
    }

    //  Tear down the connection if we have failed to decode input data
    //  or the session has rejected the message.
    if (rc == -1) {
        if (errno != EAGAIN) {
            error (protocol_error);
            return;
        }
        _input_stopped = true;
        reset_pollin (_handle);
    }

    _session->flush ();
}

void zmq::stream_engine_t::out_event ()
{
    zmq_assert (!_io_error);

    //  If write buffer is empty, try to read new data from the encoder.
    if (!_outsize) {
        //  Even when we stop polling as soon as there is no
        //  data to send, the poller may invoke out_event one
        //  more time due to 'speculative write' optimisation.
        if (unlikely (_encoder == NULL)) {
            zmq_assert (_handshaking);
            return;
        }

        _outpos = NULL;
        _outsize = _encoder->encode (&_outpos, 0);

        while (_outsize < static_cast<size_t> (out_batch_size)) {
            if ((this->*_next_msg) (&_tx_msg) == -1)
                break;
            _encoder->load_msg (&_tx_msg);
            unsigned char *bufptr = _outpos + _outsize;
            size_t n = _encoder->encode (&bufptr, out_batch_size - _outsize);
            zmq_assert (n > 0);
            if (_outpos == NULL)
                _outpos = bufptr;
            _outsize += n;
        }

        //  If there is no data to send, stop polling for output.
        if (_outsize == 0) {
            _output_stopped = true;
            reset_pollout (_handle);
            return;
        }
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket. Note that amount of data to write can be
    //  arbitrarily large. However, we assume that underlying TCP layer has
    //  limited transmission buffer and thus the actual number of bytes
    //  written should be reasonably modest.
    const int nbytes = tcp_write (_s, _outpos, _outsize);

    //  IO error has occurred. We stop waiting for output events.
    //  The engine is not terminated until we detect input error;
    //  this is necessary to prevent losing incoming messages.
    if (nbytes == -1) {
        reset_pollout (_handle);
        return;
    }

    _outpos += nbytes;
    _outsize -= nbytes;

    //  If we are still handshaking and there are no data
    //  to send, stop polling for output.
    if (unlikely (_handshaking))
        if (_outsize == 0)
            reset_pollout (_handle);
}

void zmq::stream_engine_t::restart_output ()
{
    if (unlikely (_io_error))
        return;

    if (likely (_output_stopped)) {
        set_pollout (_handle);
        _output_stopped = false;
    }

    //  Speculative write: The assumption is that at the moment new message
    //  was sent by the user the socket is probably available for writing.
    //  Thus we try to write the data to socket avoiding polling for POLLOUT.
    //  Consequently, the latency should be better in request/reply scenarios.
    out_event ();
}

bool zmq::stream_engine_t::restart_input ()
{
    zmq_assert (_input_stopped);
    zmq_assert (_session != NULL);
    zmq_assert (_decoder != NULL);

    int rc = (this->*_process_msg) (_decoder->msg ());
    if (rc == -1) {
        if (errno == EAGAIN)
            _session->flush ();
        else {
            error (protocol_error);
            return false;
        }
        return true;
    }

    while (_insize > 0) {
        size_t processed = 0;
        rc = _decoder->decode (_inpos, _insize, processed);
        zmq_assert (processed <= _insize);
        _inpos += processed;
        _insize -= processed;
        if (rc == 0 || rc == -1)
            break;
        rc = (this->*_process_msg) (_decoder->msg ());
        if (rc == -1)
            break;
    }

    if (rc == -1 && errno == EAGAIN)
        _session->flush ();
    else if (_io_error) {
        error (connection_error);
        return false;
    } else if (rc == -1) {
        error (protocol_error);
        return false;
    }

    else {
        _input_stopped = false;
        set_pollin (_handle);
        _session->flush ();

        //  Speculative read.
        in_event ();
    }

    return true;
}

//  Position of the revision field in the greeting.
const size_t revision_pos = 10;

bool zmq::stream_engine_t::handshake ()
{
    zmq_assert (_handshaking);
    zmq_assert (_greeting_bytes_read < _greeting_size);
    //  Receive the greeting.
    const int rc = receive_greeting ();
    if (rc == -1)
        return false;
    const bool unversioned = rc != 0;

    if (!(this
            ->*select_handshake_fun (unversioned,
                                     _greeting_recv[revision_pos])) ())
        return false;

    // Start polling for output if necessary.
    if (_outsize == 0)
        set_pollout (_handle);

    //  Handshaking was successful.
    //  Switch into the normal message flow.
    _handshaking = false;

    if (_has_handshake_timer) {
        cancel_timer (handshake_timer_id);
        _has_handshake_timer = false;
    }

    return true;
}

int zmq::stream_engine_t::receive_greeting ()
{
    bool unversioned = false;
    while (_greeting_bytes_read < _greeting_size) {
        const int n = tcp_read (_s, _greeting_recv + _greeting_bytes_read,
                                _greeting_size - _greeting_bytes_read);
        if (n == 0) {
            errno = EPIPE;
            error (connection_error);
            return -1;
        }
        if (n == -1) {
            if (errno != EAGAIN)
                error (connection_error);
            return -1;
        }

        _greeting_bytes_read += n;

        //  We have received at least one byte from the peer.
        //  If the first byte is not 0xff, we know that the
        //  peer is using unversioned protocol.
        if (_greeting_recv[0] != 0xff) {
            unversioned = true;
            break;
        }

        if (_greeting_bytes_read < signature_size)
            continue;

        //  Inspect the right-most bit of the 10th byte (which coincides
        //  with the 'flags' field if a regular message was sent).
        //  Zero indicates this is a header of a routing id message
        //  (i.e. the peer is using the unversioned protocol).
        if (!(_greeting_recv[9] & 0x01)) {
            unversioned = true;
            break;
        }

        //  The peer is using versioned protocol.
        receive_greeting_versioned ();
    }
    return unversioned ? 1 : 0;
}

void zmq::stream_engine_t::receive_greeting_versioned ()
{
    //  Send the major version number.
    if (_outpos + _outsize == _greeting_send + signature_size) {
        if (_outsize == 0)
            set_pollout (_handle);
        _outpos[_outsize++] = 3; //  Major version number
    }

    if (_greeting_bytes_read > signature_size) {
        if (_outpos + _outsize == _greeting_send + signature_size + 1) {
            if (_outsize == 0)
                set_pollout (_handle);

            //  Use ZMTP/2.0 to talk to older peers.
            if (_greeting_recv[revision_pos] == ZMTP_1_0
                || _greeting_recv[revision_pos] == ZMTP_2_0)
                _outpos[_outsize++] = _options.type;
            else {
                _outpos[_outsize++] = 0; //  Minor version number
                memset (_outpos + _outsize, 0, 20);

                zmq_assert (_options.mechanism == ZMQ_NULL
                            || _options.mechanism == ZMQ_PLAIN
                            || _options.mechanism == ZMQ_CURVE
                            || _options.mechanism == ZMQ_GSSAPI);

                if (_options.mechanism == ZMQ_NULL)
                    memcpy (_outpos + _outsize, "NULL", 4);
                else if (_options.mechanism == ZMQ_PLAIN)
                    memcpy (_outpos + _outsize, "PLAIN", 5);
                else if (_options.mechanism == ZMQ_GSSAPI)
                    memcpy (_outpos + _outsize, "GSSAPI", 6);
                else if (_options.mechanism == ZMQ_CURVE)
                    memcpy (_outpos + _outsize, "CURVE", 5);
                _outsize += 20;
                memset (_outpos + _outsize, 0, 32);
                _outsize += 32;
                _greeting_size = v3_greeting_size;
            }
        }
    }
}

zmq::stream_engine_t::handshake_fun_t
zmq::stream_engine_t::select_handshake_fun (bool unversioned,
                                            unsigned char revision)
{
    //  Is the peer using ZMTP/1.0 with no revision number?
    if (unversioned) {
        return &stream_engine_t::handshake_v1_0_unversioned;
    }
    switch (revision) {
        case ZMTP_1_0:
            return &stream_engine_t::handshake_v1_0;
        case ZMTP_2_0:
            return &stream_engine_t::handshake_v2_0;
        default:
            return &stream_engine_t::handshake_v3_0;
    }
}

bool zmq::stream_engine_t::handshake_v1_0_unversioned ()
{
    //  We send and receive rest of routing id message
    if (_session->zap_enabled ()) {
        // reject ZMTP 1.0 connections if ZAP is enabled
        error (protocol_error);
        return false;
    }

    _encoder = new (std::nothrow) v1_encoder_t (out_batch_size);
    alloc_assert (_encoder);

    _decoder =
      new (std::nothrow) v1_decoder_t (in_batch_size, _options.maxmsgsize);
    alloc_assert (_decoder);

    //  We have already sent the message header.
    //  Since there is no way to tell the encoder to
    //  skip the message header, we simply throw that
    //  header data away.
    const size_t header_size =
      _options.routing_id_size + 1 >= UCHAR_MAX ? 10 : 2;
    unsigned char tmp[10], *bufferp = tmp;

    //  Prepare the routing id message and load it into encoder.
    //  Then consume bytes we have already sent to the peer.
    const int rc = _tx_msg.init_size (_options.routing_id_size);
    zmq_assert (rc == 0);
    memcpy (_tx_msg.data (), _options.routing_id, _options.routing_id_size);
    _encoder->load_msg (&_tx_msg);
    const size_t buffer_size = _encoder->encode (&bufferp, header_size);
    zmq_assert (buffer_size == header_size);

    //  Make sure the decoder sees the data we have already received.
    _inpos = _greeting_recv;
    _insize = _greeting_bytes_read;

    //  To allow for interoperability with peers that do not forward
    //  their subscriptions, we inject a phantom subscription message
    //  message into the incoming message stream.
    if (_options.type == ZMQ_PUB || _options.type == ZMQ_XPUB)
        _subscription_required = true;

    //  We are sending our routing id now and the next message
    //  will come from the socket.
    _next_msg = &stream_engine_t::pull_msg_from_session;

    //  We are expecting routing id message.
    _process_msg = &stream_engine_t::process_routing_id_msg;

    return true;
}

bool zmq::stream_engine_t::handshake_v1_0 ()
{
    if (_session->zap_enabled ()) {
        // reject ZMTP 1.0 connections if ZAP is enabled
        error (protocol_error);
        return false;
    }

    _encoder = new (std::nothrow) v1_encoder_t (out_batch_size);
    alloc_assert (_encoder);

    _decoder =
      new (std::nothrow) v1_decoder_t (in_batch_size, _options.maxmsgsize);
    alloc_assert (_decoder);

    return true;
}

bool zmq::stream_engine_t::handshake_v2_0 ()
{
    if (_session->zap_enabled ()) {
        // reject ZMTP 2.0 connections if ZAP is enabled
        error (protocol_error);
        return false;
    }

    _encoder = new (std::nothrow) v2_encoder_t (out_batch_size);
    alloc_assert (_encoder);

    _decoder = new (std::nothrow)
      v2_decoder_t (in_batch_size, _options.maxmsgsize, _options.zero_copy);
    alloc_assert (_decoder);

    return true;
}

bool zmq::stream_engine_t::handshake_v3_0 ()
{
    _encoder = new (std::nothrow) v2_encoder_t (out_batch_size);
    alloc_assert (_encoder);

    _decoder = new (std::nothrow)
      v2_decoder_t (in_batch_size, _options.maxmsgsize, _options.zero_copy);
    alloc_assert (_decoder);

    if (_options.mechanism == ZMQ_NULL
        && memcmp (_greeting_recv + 12, "NULL\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                   20)
             == 0) {
        _mechanism = new (std::nothrow)
          null_mechanism_t (_session, _peer_address, _options);
        alloc_assert (_mechanism);
    } else if (_options.mechanism == ZMQ_PLAIN
               && memcmp (_greeting_recv + 12,
                          "PLAIN\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20)
                    == 0) {
        if (_options.as_server)
            _mechanism = new (std::nothrow)
              plain_server_t (_session, _peer_address, _options);
        else
            _mechanism = new (std::nothrow) plain_client_t (_session, _options);
        alloc_assert (_mechanism);
    }
#ifdef ZMQ_HAVE_CURVE
    else if (_options.mechanism == ZMQ_CURVE
             && memcmp (_greeting_recv + 12,
                        "CURVE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20)
                  == 0) {
        if (_options.as_server)
            _mechanism = new (std::nothrow)
              curve_server_t (_session, _peer_address, _options);
        else
            _mechanism = new (std::nothrow) curve_client_t (_session, _options);
        alloc_assert (_mechanism);
    }
#endif
#ifdef HAVE_LIBGSSAPI_KRB5
    else if (_options.mechanism == ZMQ_GSSAPI
             && memcmp (_greeting_recv + 12,
                        "GSSAPI\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20)
                  == 0) {
        if (_options.as_server)
            _mechanism = new (std::nothrow)
              gssapi_server_t (_session, _peer_address, _options);
        else
            _mechanism =
              new (std::nothrow) gssapi_client_t (_session, _options);
        alloc_assert (_mechanism);
    }
#endif
    else {
        _session->get_socket ()->event_handshake_failed_protocol (
          _session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH);
        error (protocol_error);
        return false;
    }
    _next_msg = &stream_engine_t::next_handshake_command;
    _process_msg = &stream_engine_t::process_handshake_command;

    return true;
}

int zmq::stream_engine_t::routing_id_msg (msg_t *msg_)
{
    int rc = msg_->init_size (_options.routing_id_size);
    errno_assert (rc == 0);
    if (_options.routing_id_size > 0)
        memcpy (msg_->data (), _options.routing_id, _options.routing_id_size);
    _next_msg = &stream_engine_t::pull_msg_from_session;
    return 0;
}

int zmq::stream_engine_t::process_routing_id_msg (msg_t *msg_)
{
    if (_options.recv_routing_id) {
        msg_->set_flags (msg_t::routing_id);
        int rc = _session->push_msg (msg_);
        errno_assert (rc == 0);
    } else {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
    }

    if (_subscription_required) {
        msg_t subscription;

        //  Inject the subscription message, so that also
        //  ZMQ 2.x peers receive published messages.
        int rc = subscription.init_size (1);
        errno_assert (rc == 0);
        *static_cast<unsigned char *> (subscription.data ()) = 1;
        rc = _session->push_msg (&subscription);
        errno_assert (rc == 0);
    }

    _process_msg = &stream_engine_t::push_msg_to_session;

    return 0;
}

int zmq::stream_engine_t::next_handshake_command (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    if (_mechanism->status () == mechanism_t::ready) {
        mechanism_ready ();
        return pull_and_encode (msg_);
    }
    if (_mechanism->status () == mechanism_t::error) {
        errno = EPROTO;
        return -1;
    } else {
        const int rc = _mechanism->next_handshake_command (msg_);

        if (rc == 0)
            msg_->set_flags (msg_t::command);

        return rc;
    }
}

int zmq::stream_engine_t::process_handshake_command (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);
    const int rc = _mechanism->process_handshake_command (msg_);
    if (rc == 0) {
        if (_mechanism->status () == mechanism_t::ready)
            mechanism_ready ();
        else if (_mechanism->status () == mechanism_t::error) {
            errno = EPROTO;
            return -1;
        }
        if (_output_stopped)
            restart_output ();
    }

    return rc;
}

void zmq::stream_engine_t::zap_msg_available ()
{
    zmq_assert (_mechanism != NULL);

    const int rc = _mechanism->zap_msg_available ();
    if (rc == -1) {
        error (protocol_error);
        return;
    }
    if (_input_stopped)
        if (!restart_input ())
            return;
    if (_output_stopped)
        restart_output ();
}

const zmq::endpoint_uri_pair_t &zmq::stream_engine_t::get_endpoint () const
{
    return _endpoint_uri_pair;
}

void zmq::stream_engine_t::mechanism_ready ()
{
    if (_options.heartbeat_interval > 0) {
        add_timer (_options.heartbeat_interval, heartbeat_ivl_timer_id);
        _has_heartbeat_timer = true;
    }

    bool flush_session = false;

    if (_options.recv_routing_id) {
        msg_t routing_id;
        _mechanism->peer_routing_id (&routing_id);
        const int rc = _session->push_msg (&routing_id);
        if (rc == -1 && errno == EAGAIN) {
            // If the write is failing at this stage with
            // an EAGAIN the pipe must be being shut down,
            // so we can just bail out of the routing id set.
            return;
        }
        errno_assert (rc == 0);
        flush_session = true;
    }

    if (_options.router_notify & ZMQ_NOTIFY_CONNECT) {
        msg_t connect_notification;
        connect_notification.init ();
        const int rc = _session->push_msg (&connect_notification);
        if (rc == -1 && errno == EAGAIN) {
            // If the write is failing at this stage with
            // an EAGAIN the pipe must be being shut down,
            // so we can just bail out of the notification.
            return;
        }
        errno_assert (rc == 0);
        flush_session = true;
    }

    if (flush_session)
        _session->flush ();

    _next_msg = &stream_engine_t::pull_and_encode;
    _process_msg = &stream_engine_t::write_credential;

    //  Compile metadata.
    properties_t properties;
    init_properties (properties);

    //  Add ZAP properties.
    const properties_t &zap_properties = _mechanism->get_zap_properties ();
    properties.insert (zap_properties.begin (), zap_properties.end ());

    //  Add ZMTP properties.
    const properties_t &zmtp_properties = _mechanism->get_zmtp_properties ();
    properties.insert (zmtp_properties.begin (), zmtp_properties.end ());

    zmq_assert (_metadata == NULL);
    if (!properties.empty ()) {
        _metadata = new (std::nothrow) metadata_t (properties);
        alloc_assert (_metadata);
    }

    _socket->event_handshake_succeeded (_endpoint_uri_pair, 0);
}

int zmq::stream_engine_t::pull_msg_from_session (msg_t *msg_)
{
    return _session->pull_msg (msg_);
}

int zmq::stream_engine_t::push_msg_to_session (msg_t *msg_)
{
    return _session->push_msg (msg_);
}

int zmq::stream_engine_t::push_raw_msg_to_session (msg_t *msg_)
{
    if (_metadata && _metadata != msg_->metadata ())
        msg_->set_metadata (_metadata);
    return push_msg_to_session (msg_);
}

int zmq::stream_engine_t::write_credential (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);
    zmq_assert (_session != NULL);

    const blob_t &credential = _mechanism->get_user_id ();
    if (credential.size () > 0) {
        msg_t msg;
        int rc = msg.init_size (credential.size ());
        zmq_assert (rc == 0);
        memcpy (msg.data (), credential.data (), credential.size ());
        msg.set_flags (msg_t::credential);
        rc = _session->push_msg (&msg);
        if (rc == -1) {
            rc = msg.close ();
            errno_assert (rc == 0);
            return -1;
        }
    }
    _process_msg = &stream_engine_t::decode_and_push;
    return decode_and_push (msg_);
}

int zmq::stream_engine_t::pull_and_encode (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    if (_session->pull_msg (msg_) == -1)
        return -1;
    if (_mechanism->encode (msg_) == -1)
        return -1;
    return 0;
}

int zmq::stream_engine_t::decode_and_push (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    if (_mechanism->decode (msg_) == -1)
        return -1;

    if (_has_timeout_timer) {
        _has_timeout_timer = false;
        cancel_timer (heartbeat_timeout_timer_id);
    }

    if (_has_ttl_timer) {
        _has_ttl_timer = false;
        cancel_timer (heartbeat_ttl_timer_id);
    }

    if (msg_->flags () & msg_t::command) {
        process_command_message (msg_);
    }

    if (_metadata)
        msg_->set_metadata (_metadata);
    if (_session->push_msg (msg_) == -1) {
        if (errno == EAGAIN)
            _process_msg = &stream_engine_t::push_one_then_decode_and_push;
        return -1;
    }
    return 0;
}

int zmq::stream_engine_t::push_one_then_decode_and_push (msg_t *msg_)
{
    const int rc = _session->push_msg (msg_);
    if (rc == 0)
        _process_msg = &stream_engine_t::decode_and_push;
    return rc;
}

void zmq::stream_engine_t::error (error_reason_t reason_)
{
    if (_options.raw_socket && _options.raw_notify) {
        //  For raw sockets, send a final 0-length message to the application
        //  so that it knows the peer has been disconnected.
        msg_t terminator;
        terminator.init ();
        (this->*_process_msg) (&terminator);
        terminator.close ();
    }
    zmq_assert (_session);

    if ((_options.router_notify & ZMQ_NOTIFY_DISCONNECT) && !_handshaking) {
        // For router sockets with disconnect notification, rollback
        // any incomplete message in the pipe, and push the disconnect
        // notification message.
        _session->rollback ();

        msg_t disconnect_notification;
        disconnect_notification.init ();
        _session->push_msg (&disconnect_notification);
    }

    // protocol errors have been signaled already at the point where they occurred
    if (reason_ != protocol_error
        && (_mechanism == NULL
            || _mechanism->status () == mechanism_t::handshaking)) {
        int err = errno;
        _socket->event_handshake_failed_no_detail (_endpoint_uri_pair, err);
    }

    _socket->event_disconnected (_endpoint_uri_pair, _s);
    _session->flush ();
    _session->engine_error (reason_);
    unplug ();
    delete this;
}

void zmq::stream_engine_t::set_handshake_timer ()
{
    zmq_assert (!_has_handshake_timer);

    if (!_options.raw_socket && _options.handshake_ivl > 0) {
        add_timer (_options.handshake_ivl, handshake_timer_id);
        _has_handshake_timer = true;
    }
}

bool zmq::stream_engine_t::init_properties (properties_t &properties_)
{
    if (_peer_address.empty ())
        return false;
    properties_.ZMQ_MAP_INSERT_OR_EMPLACE (
      std::string (ZMQ_MSG_PROPERTY_PEER_ADDRESS), _peer_address);

    //  Private property to support deprecated SRCFD
    std::ostringstream stream;
    stream << static_cast<int> (_s);
    std::string fd_string = stream.str ();
    properties_.ZMQ_MAP_INSERT_OR_EMPLACE (std::string ("__fd"),
                                           ZMQ_MOVE (fd_string));
    return true;
}

void zmq::stream_engine_t::timer_event (int id_)
{
    if (id_ == handshake_timer_id) {
        _has_handshake_timer = false;
        //  handshake timer expired before handshake completed, so engine fail
        error (timeout_error);
    } else if (id_ == heartbeat_ivl_timer_id) {
        _next_msg = &stream_engine_t::produce_ping_message;
        out_event ();
        add_timer (_options.heartbeat_interval, heartbeat_ivl_timer_id);
    } else if (id_ == heartbeat_ttl_timer_id) {
        _has_ttl_timer = false;
        error (timeout_error);
    } else if (id_ == heartbeat_timeout_timer_id) {
        _has_timeout_timer = false;
        error (timeout_error);
    } else
        // There are no other valid timer ids!
        assert (false);
}

int zmq::stream_engine_t::produce_ping_message (msg_t *msg_)
{
    // 16-bit TTL + \4PING == 7
    const size_t ping_ttl_len = msg_t::ping_cmd_name_size + 2;
    zmq_assert (_mechanism != NULL);

    int rc = msg_->init_size (ping_ttl_len);
    errno_assert (rc == 0);
    msg_->set_flags (msg_t::command);
    // Copy in the command message
    memcpy (msg_->data (), "\4PING", msg_t::ping_cmd_name_size);

    uint16_t ttl_val = htons (_options.heartbeat_ttl);
    memcpy (static_cast<uint8_t *> (msg_->data ()) + msg_t::ping_cmd_name_size,
            &ttl_val, sizeof (ttl_val));

    rc = _mechanism->encode (msg_);
    _next_msg = &stream_engine_t::pull_and_encode;
    if (!_has_timeout_timer && _heartbeat_timeout > 0) {
        add_timer (_heartbeat_timeout, heartbeat_timeout_timer_id);
        _has_timeout_timer = true;
    }
    return rc;
}

int zmq::stream_engine_t::produce_pong_message (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    int rc = msg_->move (_pong_msg);
    errno_assert (rc == 0);

    rc = _mechanism->encode (msg_);
    _next_msg = &stream_engine_t::pull_and_encode;
    return rc;
}

int zmq::stream_engine_t::process_heartbeat_message (msg_t *msg_)
{
    if (msg_->is_ping ()) {
        // 16-bit TTL + \4PING == 7
        const size_t ping_ttl_len = msg_t::ping_cmd_name_size + 2;
        const size_t ping_max_ctx_len = 16;
        uint16_t remote_heartbeat_ttl;

        // Get the remote heartbeat TTL to setup the timer
        memcpy (&remote_heartbeat_ttl,
                static_cast<uint8_t *> (msg_->data ())
                  + msg_t::ping_cmd_name_size,
                ping_ttl_len - msg_t::ping_cmd_name_size);
        remote_heartbeat_ttl = ntohs (remote_heartbeat_ttl);
        // The remote heartbeat is in 10ths of a second
        // so we multiply it by 100 to get the timer interval in ms.
        remote_heartbeat_ttl *= 100;

        if (!_has_ttl_timer && remote_heartbeat_ttl > 0) {
            add_timer (remote_heartbeat_ttl, heartbeat_ttl_timer_id);
            _has_ttl_timer = true;
        }

        //  As per ZMTP 3.1 the PING command might contain an up to 16 bytes
        //  context which needs to be PONGed back, so build the pong message
        //  here and store it. Truncate it if it's too long.
        //  Given the engine goes straight to out_event, sequential PINGs will
        //  not be a problem.
        const size_t context_len =
          std::min (msg_->size () - ping_ttl_len, ping_max_ctx_len);
        const int rc =
          _pong_msg.init_size (msg_t::ping_cmd_name_size + context_len);
        errno_assert (rc == 0);
        _pong_msg.set_flags (msg_t::command);
        memcpy (_pong_msg.data (), "\4PONG", msg_t::ping_cmd_name_size);
        if (context_len > 0)
            memcpy (static_cast<uint8_t *> (_pong_msg.data ())
                      + msg_t::ping_cmd_name_size,
                    static_cast<uint8_t *> (msg_->data ()) + ping_ttl_len,
                    context_len);

        _next_msg = &stream_engine_t::produce_pong_message;
        out_event ();
    }

    return 0;
}

int zmq::stream_engine_t::process_command_message (msg_t *msg_)
{
    const uint8_t cmd_name_size =
      *(static_cast<const uint8_t *> (msg_->data ()));
    const size_t ping_name_size = msg_t::ping_cmd_name_size - 1;
    const size_t sub_name_size = msg_t::sub_cmd_name_size - 1;
    const size_t cancel_name_size = msg_t::cancel_cmd_name_size - 1;
    //  Malformed command
    if (unlikely (msg_->size () < cmd_name_size + sizeof (cmd_name_size)))
        return -1;

    uint8_t *cmd_name = (static_cast<uint8_t *> (msg_->data ())) + 1;
    if (cmd_name_size == ping_name_size
        && memcmp (cmd_name, "PING", cmd_name_size) == 0)
        msg_->set_flags (zmq::msg_t::ping);
    if (cmd_name_size == ping_name_size
        && memcmp (cmd_name, "PONG", cmd_name_size) == 0)
        msg_->set_flags (zmq::msg_t::pong);
    if (cmd_name_size == sub_name_size
        && memcmp (cmd_name, "SUBSCRIBE", cmd_name_size) == 0)
        msg_->set_flags (zmq::msg_t::subscribe);
    if (cmd_name_size == cancel_name_size
        && memcmp (cmd_name, "CANCEL", cmd_name_size) == 0)
        msg_->set_flags (zmq::msg_t::cancel);

    if (msg_->is_ping () || msg_->is_pong ())
        return process_heartbeat_message (msg_);

    return 0;
}
