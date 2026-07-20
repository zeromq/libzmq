/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#if defined ZMQ_HAVE_LINUX

#include "shm_engine.hpp"

#include "err.hpp"
#include "ip.hpp"
#include "session_base.hpp"
#include "socket_base.hpp"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
const uint32_t shm_slot_count = 8;
const size_t shm_payload_capacity = 8 * 1024 * 1024;
}

zmq::shm_engine_t::shm_engine_t (
  fd_t fd_,
  fd_t release_fd_,
  shm_state_t *state_,
  const endpoint_uri_pair_t &endpoint_) :
    _plugged (false),
    _fd (fd_),
    _release_fd (release_fd_),
    _state (state_),
    _session (NULL),
    _handle (static_cast<handle_t> (NULL)),
    _release_handle (static_cast<handle_t> (NULL)),
    _endpoint (endpoint_),
    _receive_position (0),
    _out_pending (false),
    _in_pending (false),
    _peer_closed (false)
{
    zmq_assert (_state);
    const int rc = _out_msg.init ();
    errno_assert (rc == 0);
    const int rc2 = _in_msg.init ();
    errno_assert (rc2 == 0);
    unblock_socket (_fd);
}

zmq::shm_engine_t::~shm_engine_t ()
{
    zmq_assert (!_plugged);
    int rc = _out_msg.close ();
    errno_assert (rc == 0);
    rc = _in_msg.close ();
    errno_assert (rc == 0);
    //  Do not call back into the owning socket here.  The engine may outlive
    //  zmq_close() on the socket while the session is drained asynchronously,
    //  in which case the socket mutexes have already been destroyed.  The
    //  socket releases its registered shm_state_t reference from the socket
    //  thread; this engine only owns the reference passed at construction.
    _state->clear_control_fd (_fd);
    if (_fd != retired_fd) {
        rc = close (_fd);
        errno_assert (rc == 0);
        _fd = retired_fd;
    }
    if (_release_fd != retired_fd) {
        rc = close (_release_fd);
        errno_assert (rc == 0);
        _release_fd = retired_fd;
    }
    _state->drop_ref ();
    _state = NULL;
}

size_t zmq::shm_engine_t::mapping_size ()
{
    return shm_channel_t::memory_size (shm_slot_count,
                                       shm_payload_capacity);
}

int zmq::shm_engine_t::initialize_mapping (void *mapping_,
                                           size_t mapping_size_)
{
    return shm_channel_t::initialize (mapping_, mapping_size_, shm_slot_count,
                                      shm_payload_capacity);
}

bool zmq::shm_engine_t::valid () const
{
    return _fd != retired_fd && _release_fd != retired_fd && _state->valid ();
}

void zmq::shm_engine_t::plug (io_thread_t *io_thread_,
                              session_base_t *session_)
{
    zmq_assert (!_plugged);
    zmq_assert (session_);
    _plugged = true;
    _session = session_;
    _state->set_control_fd (_fd);
    _session->get_socket ()->register_shm_state (_state);
    io_object_t::plug (io_thread_);
    _handle = add_fd (_fd);
    _release_handle = add_fd (_release_fd);
    set_pollin (_handle);
    set_pollin (_release_handle);
    restart_output ();
}

void zmq::shm_engine_t::terminate ()
{
    zmq_assert (_plugged);
    _plugged = false;
    rm_fd (_handle);
    rm_fd (_release_handle);
    _handle = static_cast<handle_t> (NULL);
    _release_handle = static_cast<handle_t> (NULL);
    io_object_t::unplug ();
    delete this;
}

bool zmq::shm_engine_t::notify_peer (bool allow_closed_)
{
    if (_peer_closed)
        return allow_closed_;

    const unsigned char byte = 1;
    ssize_t rc;
    do {
        rc = send (_fd, &byte, sizeof byte, MSG_NOSIGNAL);
    } while (rc == -1 && errno == EINTR);
    if (rc == 1 || (rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)))
        return true;
    if (allow_closed_ && rc == -1
        && (errno == EPIPE || errno == ECONNRESET || errno == ENOTCONN)) {
        _peer_closed = true;
        return true;
    }
    error (connection_error);
    return false;
}

bool zmq::shm_engine_t::pump_output ()
{
    while (true) {
        if (!_out_pending) {
            const int rc = _session->pull_msg (&_out_msg);
            if (rc == -1) {
                errno_assert (errno == EAGAIN);
                return true;
            }
            _out_pending = true;
        }

        if (_out_msg.size () > shm_payload_capacity) {
            error (protocol_error);
            return false;
        }

        uint64_t position = 0;
        void *const data = _state->try_reserve_copy (
          _out_msg.size (),
          static_cast<unsigned char> (_out_msg.flags () & ~msg_t::shared),
          &position);
        if (!data)
            return true;

        if (_out_msg.size ())
            memcpy (data, _out_msg.data (), _out_msg.size ());
        _state->publish_copy (position);

        int rc = _out_msg.close ();
        errno_assert (rc == 0);
        rc = _out_msg.init ();
        errno_assert (rc == 0);
        _out_pending = false;

        if (!notify_peer (false))
            return false;
    }
}

bool zmq::shm_engine_t::pump_input ()
{
    while (true) {
        if (_in_pending) {
            if (_session->push_msg (&_in_msg) == -1) {
                errno_assert (errno == EAGAIN);
                return true;
            }
            _in_pending = false;
        }

        const void *data = NULL;
        size_t size = 0;
        unsigned char flags = 0;
        if (!_state->try_receive (_receive_position, &data, &size, &flags)) {
            _session->flush ();
            return true;
        }

        int rc = _in_msg.close ();
        errno_assert (rc == 0);
        rc = _state->init_received_message (&_in_msg, _receive_position, data,
                                            size, flags);
        if (rc == -1) {
            const int saved_errno = errno;
            rc = _in_msg.init ();
            errno_assert (rc == 0);
            errno = saved_errno;
            error (protocol_error);
            return false;
        }
        ++_receive_position;

        if (_session->push_msg (&_in_msg) == -1) {
            errno_assert (errno == EAGAIN);
            _in_pending = true;
            _session->flush ();
            return true;
        }
    }
}

void zmq::shm_engine_t::in_event ()
{
    uint64_t releases = 0;
    while (true) {
        const ssize_t rc = read (_release_fd, &releases, sizeof releases);
        if (rc == static_cast<ssize_t> (sizeof releases))
            continue;
        if (rc == -1 && errno == EINTR)
            continue;
        break;
    }

    unsigned char buffer[64];
    while (true) {
        const ssize_t rc = recv (_fd, buffer, sizeof buffer, 0);
        if (rc > 0)
            continue;
        if (rc == 0) {
            _peer_closed = true;
            break;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        error (connection_error);
        return;
    }

    if (!pump_input ())
        return;
    if (_peer_closed) {
        if (input_drained ())
            error (connection_error);
        return;
    }
    pump_output ();
}

bool zmq::shm_engine_t::restart_input ()
{
    if (!pump_input ())
        return false;
    if (_peer_closed && input_drained ()) {
        error (connection_error);
        return false;
    }
    return true;
}

void zmq::shm_engine_t::restart_output ()
{
    pump_output ();
}

const zmq::endpoint_uri_pair_t &zmq::shm_engine_t::get_endpoint () const
{
    return _endpoint;
}

bool zmq::shm_engine_t::input_drained () const
{
    if (_in_pending)
        return false;
    const void *data = NULL;
    size_t size = 0;
    unsigned char flags = 0;
    return !_state->try_receive (_receive_position, &data, &size, &flags);
}

void zmq::shm_engine_t::error (error_reason_t reason_)
{
    zmq_assert (_session);
    _session->engine_error (false, reason_);
    terminate ();
}

#endif
