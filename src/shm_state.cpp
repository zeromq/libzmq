/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#if defined ZMQ_HAVE_LINUX

#include "shm_state.hpp"

#include "err.hpp"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

zmq::shm_state_t *zmq::shm_state_t::create (void *mapping_,
                                            size_t mapping_size_,
                                            bool server_,
                                            fd_t control_fd_,
                                            fd_t release_fd_)
{
    shm_state_t *const state = new (std::nothrow)
      shm_state_t (mapping_, mapping_size_, server_, control_fd_, release_fd_);
    alloc_assert (state);
    if (!state->valid ()) {
        delete state;
        errno = EPROTO;
        return NULL;
    }
    return state;
}

zmq::shm_state_t::shm_state_t (void *mapping_,
                               size_t mapping_size_,
                               bool server_,
                               fd_t control_fd_,
                               fd_t release_fd_) :
    _refs (1),
    _mapping (mapping_),
    _mapping_size (mapping_size_),
    _channel (new (std::nothrow)
                shm_channel_t (mapping_, mapping_size_, server_)),
    _control_fd (control_fd_),
    _release_fd (release_fd_),
    _send_position (0),
    _send_reserved (false),
    _direct_mode (false)
{
    alloc_assert (_channel);
}

zmq::shm_state_t::~shm_state_t ()
{
    delete _channel;
    _channel = NULL;
    if (_mapping != MAP_FAILED) {
        const int rc = munmap (_mapping, _mapping_size);
        errno_assert (rc == 0);
        _mapping = MAP_FAILED;
    }
    if (_release_fd != retired_fd) {
        const int rc = close (_release_fd);
        errno_assert (rc == 0);
        _release_fd = retired_fd;
    }
}

void zmq::shm_state_t::add_ref ()
{
    _refs.add (1);
}

void zmq::shm_state_t::drop_ref ()
{
    if (!_refs.sub (1))
        delete this;
}

bool zmq::shm_state_t::valid () const
{
    return _mapping != MAP_FAILED && _channel && _channel->valid ();
}

void zmq::shm_state_t::set_control_fd (fd_t fd_)
{
    scoped_lock_t lock (_sync);
    _control_fd = fd_;
}

void zmq::shm_state_t::clear_control_fd (fd_t fd_)
{
    scoped_lock_t lock (_sync);
    if (_control_fd == fd_)
        _control_fd = retired_fd;
}

uint64_t zmq::shm_state_t::token_magic ()
{
    return UINT64_C (0x5a4d5153484d544b);
}

zmq::shm_state_t::token_t *
zmq::shm_state_t::create_token (token_kind_t kind_, uint64_t position_)
{
    token_t *const token = static_cast<token_t *> (malloc (sizeof (token_t)));
    if (!token)
        return NULL;
    token->magic = token_magic ();
    token->state = this;
    token->position = position_;
    token->kind = static_cast<unsigned char> (kind_);
    token->published = 0;
    add_ref ();
    return token;
}

zmq::shm_state_t::token_t *
zmq::shm_state_t::token_from_message (const msg_t *msg_)
{
    void *hint = NULL;
    if (!msg_ || !msg_->external_storage_matches (&free_message, &hint))
        return NULL;
    token_t *const token = static_cast<token_t *> (hint);
    if (!token || token->magic != token_magic () || !token->state)
        return NULL;
    return token;
}

bool zmq::shm_state_t::is_shm_message (const msg_t *msg_)
{
    return token_from_message (msg_) != NULL;
}

int zmq::shm_state_t::init_direct_message (msg_t *msg_, size_t size_)
{
    if (!msg_ || size_ == 0) {
        errno = EINVAL;
        return -1;
    }

    scoped_lock_t lock (_sync);
    if (_control_fd == retired_fd) {
        errno = EAGAIN;
        return -1;
    }
    if (_send_reserved) {
        errno = EAGAIN;
        return -1;
    }

    void *const data =
      _channel->try_reserve_send (_send_position, size_, 0);
    if (!data) {
        errno = EAGAIN;
        return -1;
    }

    token_t *const token = create_token (direct_send_token, _send_position);
    if (!token) {
        errno = ENOMEM;
        return -1;
    }
    _send_reserved = true;
    const int rc = msg_->init_external_storage (&token->content, data, size_,
                                                &free_message, token);
    if (rc != 0) {
        _send_reserved = false;
        token->magic = 0;
        free (token);
        drop_ref ();
        return rc;
    }
    _direct_mode = true;
    return 0;
}

bool zmq::shm_state_t::notify_data ()
{
    const unsigned char byte = 1;
    ssize_t rc;
    do {
        rc = send (_control_fd, &byte, sizeof byte, MSG_NOSIGNAL);
    } while (rc == -1 && errno == EINTR);
    return rc == 1
           || (rc == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

int zmq::shm_state_t::send_direct_message (msg_t *msg_, int flags_)
{
    token_t *const token = token_from_message (msg_);
    if (!token || token->state != this || token->kind != direct_send_token) {
        errno = EINVAL;
        return -1;
    }
    if (msg_->flags () & msg_t::shared) {
        errno = EINVAL;
        return -1;
    }

    const size_t size = msg_->size ();
    {
        scoped_lock_t lock (_sync);
        if (!_send_reserved || token->position != _send_position
            || _control_fd == retired_fd) {
            errno = EAGAIN;
            return -1;
        }
        const unsigned char message_flags =
          (flags_ & ZMQ_SNDMORE) ? msg_t::more : 0;
        if (!_channel->set_send_flags (_send_position, message_flags)) {
            errno = EFAULT;
            return -1;
        }
        _channel->publish_send (_send_position++);
        _send_reserved = false;
        token->published = 1;
        notify_data ();
    }

    int rc = msg_->close ();
    errno_assert (rc == 0);
    rc = msg_->init ();
    errno_assert (rc == 0);
    return static_cast<int> (size > INT_MAX ? INT_MAX : size);
}

void *zmq::shm_state_t::try_reserve_copy (size_t size_,
                                          unsigned char flags_,
                                          uint64_t *position_)
{
    scoped_lock_t lock (_sync);
    if (_send_reserved || _direct_mode)
        return NULL;
    void *const data =
      _channel->try_reserve_send (_send_position, size_, flags_);
    if (!data)
        return NULL;
    _send_reserved = true;
    *position_ = _send_position;
    return data;
}

void zmq::shm_state_t::publish_copy (uint64_t position_)
{
    scoped_lock_t lock (_sync);
    zmq_assert (_send_reserved && position_ == _send_position);
    _channel->publish_send (_send_position++);
    _send_reserved = false;
}

bool zmq::shm_state_t::try_receive (uint64_t position_,
                                    const void **data_,
                                    size_t *size_,
                                    unsigned char *flags_) const
{
    return _channel->try_receive (position_, data_, size_, flags_);
}

int zmq::shm_state_t::init_received_message (msg_t *msg_,
                                             uint64_t position_,
                                             const void *data_,
                                             size_t size_,
                                             unsigned char flags_)
{
    token_t *const token = create_token (receive_token, position_);
    if (!token) {
        errno = ENOMEM;
        return -1;
    }
    const int rc = msg_->init_external_storage (
      &token->content, const_cast<void *> (data_), size_, &free_message, token);
    if (rc != 0) {
        token->magic = 0;
        free (token);
        drop_ref ();
        return rc;
    }
    msg_->set_flags (static_cast<unsigned char> (flags_ & ~msg_t::shared));
    return 0;
}

void zmq::shm_state_t::cancel_direct (uint64_t position_)
{
    scoped_lock_t lock (_sync);
    if (_send_reserved && position_ == _send_position)
        _send_reserved = false;
}

void zmq::shm_state_t::release_receive (uint64_t position_)
{
    _channel->release_receive (position_);
    if (_release_fd != retired_fd) {
        const uint64_t value = 1;
        ssize_t rc;
        do {
            rc = write (_release_fd, &value, sizeof value);
        } while (rc == -1 && errno == EINTR);
    }
}

void zmq::shm_state_t::free_message (void *, void *hint_)
{
    token_t *const token = static_cast<token_t *> (hint_);
    zmq_assert (token && token->magic == token_magic ());
    shm_state_t *const state = token->state;
    if (token->kind == receive_token)
        state->release_receive (token->position);
    else if (!token->published)
        state->cancel_direct (token->position);
    token->magic = 0;
    free (token);
    state->drop_ref ();
}

#endif
