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

#include "stream_engine_base.hpp"
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
        if (!getsockopt (s_, 0, LOCAL_PEERCRED, &cred, &size)
            && cred.cr_version == XUCRED_VERSION) {
            std::ostringstream buf;
            buf << ":" << cred.cr_uid << ":";
            if (cred.cr_ngroups > 0)
                buf << cred.cr_groups[0];
            buf << ":";
            peer_address += buf.str ();
        }
    }
#endif

    return peer_address;
}

zmq::stream_engine_base_t::stream_engine_base_t (
  fd_t fd_,
  const options_t &options_,
  const endpoint_uri_pair_t &endpoint_uri_pair_,
  bool has_handshake_stage_) :
    _options (options_),
    _inpos (NULL),
    _insize (0),
    _decoder (NULL),
    _outpos (NULL),
    _outsize (0),
    _encoder (NULL),
    _mechanism (NULL),
    _next_msg (NULL),
    _process_msg (NULL),
    _metadata (NULL),
    _input_stopped (false),
    _output_stopped (false),
    _endpoint_uri_pair (endpoint_uri_pair_),
    _has_handshake_timer (false),
    _has_ttl_timer (false),
    _has_timeout_timer (false),
    _has_heartbeat_timer (false),
    _peer_address (get_peer_address (fd_)),
    _s (fd_),
    _handle (static_cast<handle_t> (NULL)),
    _plugged (false),
    _handshaking (true),
    _io_error (false),
    _session (NULL),
    _socket (NULL),
    _has_handshake_stage (has_handshake_stage_)
{
    const int rc = _tx_msg.init ();
    errno_assert (rc == 0);

    //  Put the socket into non-blocking mode.
    unblock_socket (_s);
}

zmq::stream_engine_base_t::~stream_engine_base_t ()
{
    zmq_assert (!_plugged);

    if (_s != retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        const int rc = closesocket (_s);
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

    const int rc = _tx_msg.close ();
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

void zmq::stream_engine_base_t::plug (io_thread_t *io_thread_,
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

    plug_internal ();
}

void zmq::stream_engine_base_t::unplug ()
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

void zmq::stream_engine_base_t::terminate ()
{
    unplug ();
    delete this;
}

void zmq::stream_engine_base_t::in_event ()
{
    // ignore errors
    const bool res = in_event_internal ();
    LIBZMQ_UNUSED (res);
}

bool zmq::stream_engine_base_t::in_event_internal ()
{
    zmq_assert (!_io_error);

    //  If still handshaking, receive and process the greeting message.
    if (unlikely (_handshaking)) {
        if (handshake ()) {
            //  Handshaking was successful.
            //  Switch into the normal message flow.
            _handshaking = false;

            if (_mechanism == NULL && _has_handshake_stage)
                _session->engine_ready ();
        } else
            return false;
    }


    zmq_assert (_decoder);

    //  If there has been an I/O error, stop polling.
    if (_input_stopped) {
        rm_fd (_handle);
        _io_error = true;
        return true; // TODO or return false in this case too?
    }

    //  If there's no data to process in the buffer...
    if (!_insize) {
        //  Retrieve the buffer and read as much data as possible.
        //  Note that buffer can be arbitrarily large. However, we assume
        //  the underlying TCP layer has fixed buffer size and thus the
        //  number of bytes read will be always limited.
        size_t bufsize = 0;
        _decoder->get_buffer (&_inpos, &bufsize);

        const int rc = read (_inpos, bufsize);

        if (rc == -1) {
            if (errno != EAGAIN) {
                error (connection_error);
                return false;
            }
            return true;
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
            return false;
        }
        _input_stopped = true;
        reset_pollin (_handle);
    }

    _session->flush ();
    return true;
}

void zmq::stream_engine_base_t::out_event ()
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

        while (_outsize < static_cast<size_t> (_options.out_batch_size)) {
            if ((this->*_next_msg) (&_tx_msg) == -1) {
                //  ws_engine can cause an engine error and delete it, so
                //  bail out immediately to avoid use-after-free
                if (errno == ECONNRESET)
                    return;
                else
                    break;
            }
            _encoder->load_msg (&_tx_msg);
            unsigned char *bufptr = _outpos + _outsize;
            const size_t n =
              _encoder->encode (&bufptr, _options.out_batch_size - _outsize);
            zmq_assert (n > 0);
            if (_outpos == NULL)
                _outpos = bufptr;
            _outsize += n;
        }

        //  If there is no data to send, stop polling for output.
        if (_outsize == 0) {
            _output_stopped = true;
            reset_pollout ();
            return;
        }
    }

    //  If there are any data to write in write buffer, write as much as
    //  possible to the socket. Note that amount of data to write can be
    //  arbitrarily large. However, we assume that underlying TCP layer has
    //  limited transmission buffer and thus the actual number of bytes
    //  written should be reasonably modest.
    const int nbytes = write (_outpos, _outsize);

    //  IO error has occurred. We stop waiting for output events.
    //  The engine is not terminated until we detect input error;
    //  this is necessary to prevent losing incoming messages.
    if (nbytes == -1) {
        reset_pollout ();
        return;
    }

    _outpos += nbytes;
    _outsize -= nbytes;

    //  If we are still handshaking and there are no data
    //  to send, stop polling for output.
    if (unlikely (_handshaking))
        if (_outsize == 0)
            reset_pollout ();
}

void zmq::stream_engine_base_t::restart_output ()
{
    if (unlikely (_io_error))
        return;

    if (likely (_output_stopped)) {
        set_pollout ();
        _output_stopped = false;
    }

    //  Speculative write: The assumption is that at the moment new message
    //  was sent by the user the socket is probably available for writing.
    //  Thus we try to write the data to socket avoiding polling for POLLOUT.
    //  Consequently, the latency should be better in request/reply scenarios.
    out_event ();
}

bool zmq::stream_engine_base_t::restart_input ()
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
        set_pollin ();
        _session->flush ();

        //  Speculative read.
        if (!in_event_internal ())
            return false;
    }

    return true;
}

int zmq::stream_engine_base_t::next_handshake_command (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    if (_mechanism->status () == mechanism_t::ready) {
        mechanism_ready ();
        return pull_and_encode (msg_);
    }
    if (_mechanism->status () == mechanism_t::error) {
        errno = EPROTO;
        return -1;
    }
    const int rc = _mechanism->next_handshake_command (msg_);

    if (rc == 0)
        msg_->set_flags (msg_t::command);

    return rc;
}

int zmq::stream_engine_base_t::process_handshake_command (msg_t *msg_)
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

void zmq::stream_engine_base_t::zap_msg_available ()
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

const zmq::endpoint_uri_pair_t &zmq::stream_engine_base_t::get_endpoint () const
{
    return _endpoint_uri_pair;
}

void zmq::stream_engine_base_t::mechanism_ready ()
{
    if (_options.heartbeat_interval > 0 && !_has_heartbeat_timer) {
        add_timer (_options.heartbeat_interval, heartbeat_ivl_timer_id);
        _has_heartbeat_timer = true;
    }

    if (_has_handshake_stage)
        _session->engine_ready ();

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

    _next_msg = &stream_engine_base_t::pull_and_encode;
    _process_msg = &stream_engine_base_t::write_credential;

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

    if (_has_handshake_timer) {
        cancel_timer (handshake_timer_id);
        _has_handshake_timer = false;
    }

    _socket->event_handshake_succeeded (_endpoint_uri_pair, 0);
}

int zmq::stream_engine_base_t::write_credential (msg_t *msg_)
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
    _process_msg = &stream_engine_base_t::decode_and_push;
    return decode_and_push (msg_);
}

int zmq::stream_engine_base_t::pull_and_encode (msg_t *msg_)
{
    zmq_assert (_mechanism != NULL);

    if (_session->pull_msg (msg_) == -1)
        return -1;
    if (_mechanism->encode (msg_) == -1)
        return -1;
    return 0;
}

int zmq::stream_engine_base_t::decode_and_push (msg_t *msg_)
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
            _process_msg = &stream_engine_base_t::push_one_then_decode_and_push;
        return -1;
    }
    return 0;
}

int zmq::stream_engine_base_t::push_one_then_decode_and_push (msg_t *msg_)
{
    const int rc = _session->push_msg (msg_);
    if (rc == 0)
        _process_msg = &stream_engine_base_t::decode_and_push;
    return rc;
}

int zmq::stream_engine_base_t::pull_msg_from_session (msg_t *msg_)
{
    return _session->pull_msg (msg_);
}

int zmq::stream_engine_base_t::push_msg_to_session (msg_t *msg_)
{
    return _session->push_msg (msg_);
}

void zmq::stream_engine_base_t::error (error_reason_t reason_)
{
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
        const int err = errno;
        _socket->event_handshake_failed_no_detail (_endpoint_uri_pair, err);
        // special case: connecting to non-ZMTP process which immediately drops connection,
        // or which never responds with greeting, should be treated as a protocol error
        // (i.e. stop reconnect)
        if (((reason_ == connection_error) || (reason_ == timeout_error))
            && (_options.reconnect_stop
                & ZMQ_RECONNECT_STOP_HANDSHAKE_FAILED)) {
            reason_ = protocol_error;
        }
    }

    _socket->event_disconnected (_endpoint_uri_pair, _s);
    _session->flush ();
    _session->engine_error (
      !_handshaking
        && (_mechanism == NULL
            || _mechanism->status () != mechanism_t::handshaking),
      reason_);
    unplug ();
    delete this;
}

void zmq::stream_engine_base_t::set_handshake_timer ()
{
    zmq_assert (!_has_handshake_timer);

    if (_options.handshake_ivl > 0) {
        add_timer (_options.handshake_ivl, handshake_timer_id);
        _has_handshake_timer = true;
    }
}

bool zmq::stream_engine_base_t::init_properties (properties_t &properties_)
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

void zmq::stream_engine_base_t::timer_event (int id_)
{
    if (id_ == handshake_timer_id) {
        _has_handshake_timer = false;
        //  handshake timer expired before handshake completed, so engine fail
        error (timeout_error);
    } else if (id_ == heartbeat_ivl_timer_id) {
        _next_msg = &stream_engine_base_t::produce_ping_message;
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

int zmq::stream_engine_base_t::read (void *data_, size_t size_)
{
    const int rc = zmq::tcp_read (_s, data_, size_);

    if (rc == 0) {
        // connection closed by peer
        errno = EPIPE;
        return -1;
    }

    return rc;
}

int zmq::stream_engine_base_t::write (const void *data_, size_t size_)
{
    return zmq::tcp_write (_s, data_, size_);
}
