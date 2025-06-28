/* SPDX-License-Identifier: MPL-2.0 */

// "Tell them I was a writer.
//  A maker of software.
//  A humanist. A father.
//  And many things.
//  But above all, a writer.
//  Thank You. :)"
//  - Pieter Hintjens

#include "precompiled.hpp"
#define ZMQ_TYPE_UNSAFE

#include "macros.hpp"
#include "poller.hpp"
#include "peer.hpp"

#if !defined ZMQ_HAVE_POLLER
//  On AIX platform, poll.h has to be included first to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
#if defined ZMQ_POLL_BASED_ON_POLL && !defined ZMQ_HAVE_WINDOWS
#include <poll.h>
#endif

#include "polling_util.hpp"
#endif

// TODO: determine if this is an issue, since zmq.h is being loaded from pch.
// zmq.h must be included *after* poll.h for AIX to build properly
//#include "../include/zmq.h"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#ifdef ZMQ_HAVE_VXWORKS
#include <strings.h>
#endif
#endif

// XSI vector I/O
#if defined ZMQ_HAVE_UIO
#include <sys/uio.h>
#else
struct iovec
{
    void *iov_base;
    size_t iov_len;
};
#endif

#include <string.h>
#include <stdlib.h>
#include <new>
#include <climits>

#include "proxy.hpp"
#include "socket_base.hpp"
#include "stdint.hpp"
#include "config.hpp"
#include "likely.hpp"
#include "clock.hpp"
#include "ctx.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "fd.hpp"
#include "metadata.hpp"
#include "socket_poller.hpp"
#include "timers.hpp"
#include "ip.hpp"
#include "address.hpp"

#ifdef ZMQ_HAVE_PPOLL
#include "polling_util.hpp"
#include <sys/select.h>
#endif

#if defined ZMQ_HAVE_OPENPGM
#define __PGM_WININT_H__
#include <pgm/pgm.h>
#endif

//  Compile time check whether msg_t fits into zmq_msg_t.
typedef char
  check_msg_t_size[sizeof (zmq::msg_t) == sizeof (zmq_msg_t) ? 1 : -1];

// Compile time check whether msg_t::content_t fits into zmq_msg_content_t.
// It is expected to be larger.
typedef char check_msg_content_size
  [sizeof (zmq::msg_t::content_t) <= sizeof (zmq_msg_content_t) ? 1 : -1];

void zmq_version (int *major_, int *minor_, int *patch_)
{
    *major_ = ZMQ_VERSION_MAJOR;
    *minor_ = ZMQ_VERSION_MINOR;
    *patch_ = ZMQ_VERSION_PATCH;
}


const char *zmq_strerror (int errnum_)
{
    return zmq::errno_to_string (errnum_);
}

int zmq_errno (void)
{
    return errno;
}


//  New context API

void *zmq_ctx_new (void)
{
    //  We do this before the ctx constructor since its embedded mailbox_t
    //  object needs the network to be up and running (at least on Windows).
    if (!zmq::initialize_network ()) {
        return NULL;
    }

    //  Create 0MQ context.
    zmq::ctx_t *ctx = new (std::nothrow) zmq::ctx_t;
    if (ctx) {
        if (!ctx->valid ()) {
            delete ctx;
            return NULL;
        }
    }
    return ctx;
}

int zmq_ctx_term (void *ctx_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    const int rc = (static_cast<zmq::ctx_t *> (ctx_))->terminate ();
    const int en = errno;

    //  Shut down only if termination was not interrupted by a signal.
    if (!rc || en != EINTR) {
        zmq::shutdown_network ();
    }

    errno = en;
    return rc;
}

int zmq_ctx_shutdown (void *ctx_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }
    return (static_cast<zmq::ctx_t *> (ctx_))->shutdown ();
}

int zmq_ctx_set (void *ctx_, int option_, int optval_)
{
    return zmq_ctx_set_ext (ctx_, option_, &optval_, sizeof (int));
}

int zmq_ctx_set_ext (void *ctx_,
                     int option_,
                     const void *optval_,
                     size_t optvallen_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }
    return (static_cast<zmq::ctx_t *> (ctx_))
      ->set (option_, optval_, optvallen_);
}

int zmq_ctx_get (void *ctx_, int option_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }
    return (static_cast<zmq::ctx_t *> (ctx_))->get (option_);
}

int zmq_ctx_get_ext (void *ctx_, int option_, void *optval_, size_t *optvallen_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }
    return (static_cast<zmq::ctx_t *> (ctx_))
      ->get (option_, optval_, optvallen_);
}


//  Stable/legacy context API

void *zmq_init (int io_threads_)
{
    if (io_threads_ >= 0) {
        void *ctx = zmq_ctx_new ();
        zmq_ctx_set (ctx, ZMQ_IO_THREADS, io_threads_);
        return ctx;
    }
    errno = EINVAL;
    return NULL;
}

int zmq_term (void *ctx_)
{
    return zmq_ctx_term (ctx_);
}

int zmq_ctx_destroy (void *ctx_)
{
    return zmq_ctx_term (ctx_);
}


// Sockets

static zmq::socket_base_t *as_socket_base_t (void *s_)
{
    zmq::socket_base_t *s = static_cast<zmq::socket_base_t *> (s_);
    if (!s_ || !s->check_tag ()) {
        errno = ENOTSOCK;
        return NULL;
    }
    return s;
}

void *zmq_socket (void *ctx_, int type_)
{
    if (!ctx_ || !(static_cast<zmq::ctx_t *> (ctx_))->check_tag ()) {
        errno = EFAULT;
        return NULL;
    }
    zmq::ctx_t *ctx = static_cast<zmq::ctx_t *> (ctx_);
    zmq::socket_base_t *s = ctx->create_socket (type_);
    return static_cast<void *> (s);
}

int zmq_close (void *s_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    s->close ();
    return 0;
}

int zmq_setsockopt (void *s_,
                    int option_,
                    const void *optval_,
                    size_t optvallen_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->setsockopt (option_, optval_, optvallen_);
}

int zmq_getsockopt (void *s_, int option_, void *optval_, size_t *optvallen_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->getsockopt (option_, optval_, optvallen_);
}

int zmq_socket_monitor_versioned (
  void *s_, const char *addr_, uint64_t events_, int event_version_, int type_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->monitor (addr_, events_, event_version_, type_);
}

int zmq_socket_monitor (void *s_, const char *addr_, int events_)
{
    return zmq_socket_monitor_versioned (s_, addr_, events_, 1, ZMQ_PAIR);
}

int zmq_join (void *s_, const char *group_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->join (group_);
}

int zmq_leave (void *s_, const char *group_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->leave (group_);
}

int zmq_bind (void *s_, const char *addr_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->bind (addr_);
}

int zmq_connect (void *s_, const char *addr_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->connect (addr_);
}

uint32_t zmq_connect_peer (void *s_, const char *addr_)
{
    zmq::peer_t *s = static_cast<zmq::peer_t *> (s_);
    if (!s_ || !s->check_tag ()) {
        errno = ENOTSOCK;
        return 0;
    }

    int socket_type;
    size_t socket_type_size = sizeof (socket_type);
    if (s->getsockopt (ZMQ_TYPE, &socket_type, &socket_type_size) != 0)
        return 0;

    if (socket_type != ZMQ_PEER) {
        errno = ENOTSUP;
        return 0;
    }

    return s->connect_peer (addr_);
}


int zmq_unbind (void *s_, const char *addr_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->term_endpoint (addr_);
}

int zmq_disconnect (void *s_, const char *addr_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->term_endpoint (addr_);
}

// Sending functions.

static inline int
s_sendmsg (zmq::socket_base_t *s_, zmq_msg_t *msg_, int flags_)
{
    size_t sz = zmq_msg_size (msg_);
    const int rc = s_->send (reinterpret_cast<zmq::msg_t *> (msg_), flags_);
    if (unlikely (rc < 0))
        return -1;

    //  This is what I'd like to do, my C++ fu is too weak -- PH 2016/02/09
    //  int max_msgsz = s_->parent->get (ZMQ_MAX_MSGSZ);
    size_t max_msgsz = INT_MAX;

    //  Truncate returned size to INT_MAX to avoid overflow to negative values
    return static_cast<int> (sz < max_msgsz ? sz : max_msgsz);
}

/*  To be deprecated once zmq_msg_send() is stable                           */
int zmq_sendmsg (void *s_, zmq_msg_t *msg_, int flags_)
{
    return zmq_msg_send (msg_, s_, flags_);
}

int zmq_send (void *s_, const void *buf_, size_t len_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    zmq_msg_t msg;
    int rc = zmq_msg_init_buffer (&msg, buf_, len_);
    if (unlikely (rc < 0))
        return -1;

    rc = s_sendmsg (s, &msg, flags_);
    if (unlikely (rc < 0)) {
        const int err = errno;
        const int rc2 = zmq_msg_close (&msg);
        errno_assert (rc2 == 0);
        errno = err;
        return -1;
    }
    //  Note the optimisation here. We don't close the msg object as it is
    //  empty anyway. This may change when implementation of zmq_msg_t changes.
    return rc;
}

int zmq_send_const (void *s_, const void *buf_, size_t len_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    zmq_msg_t msg;
    int rc =
      zmq_msg_init_data (&msg, const_cast<void *> (buf_), len_, NULL, NULL);
    if (rc != 0)
        return -1;

    rc = s_sendmsg (s, &msg, flags_);
    if (unlikely (rc < 0)) {
        const int err = errno;
        const int rc2 = zmq_msg_close (&msg);
        errno_assert (rc2 == 0);
        errno = err;
        return -1;
    }
    //  Note the optimisation here. We don't close the msg object as it is
    //  empty anyway. This may change when implementation of zmq_msg_t changes.
    return rc;
}


// Send multiple messages.
// TODO: this function has no man page
//
// If flag bit ZMQ_SNDMORE is set the vector is treated as
// a single multi-part message, i.e. the last message has
// ZMQ_SNDMORE bit switched off.
//
int zmq_sendiov (void *s_, iovec *a_, size_t count_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    if (unlikely (count_ <= 0 || !a_)) {
        errno = EINVAL;
        return -1;
    }

    int rc = 0;
    zmq_msg_t msg;

    for (size_t i = 0; i < count_; ++i) {
        rc = zmq_msg_init_size (&msg, a_[i].iov_len);
        if (rc != 0) {
            rc = -1;
            break;
        }
        memcpy (zmq_msg_data (&msg), a_[i].iov_base, a_[i].iov_len);
        if (i == count_ - 1)
            flags_ = flags_ & ~ZMQ_SNDMORE;
        rc = s_sendmsg (s, &msg, flags_);
        if (unlikely (rc < 0)) {
            const int err = errno;
            const int rc2 = zmq_msg_close (&msg);
            errno_assert (rc2 == 0);
            errno = err;
            rc = -1;
            break;
        }
    }
    return rc;
}

// Receiving functions.

static int s_recvmsg (zmq::socket_base_t *s_, zmq_msg_t *msg_, int flags_)
{
    const int rc = s_->recv (reinterpret_cast<zmq::msg_t *> (msg_), flags_);
    if (unlikely (rc < 0))
        return -1;

    //  Truncate returned size to INT_MAX to avoid overflow to negative values
    const size_t sz = zmq_msg_size (msg_);
    return static_cast<int> (sz < INT_MAX ? sz : INT_MAX);
}

/*  To be deprecated once zmq_msg_recv() is stable                           */
int zmq_recvmsg (void *s_, zmq_msg_t *msg_, int flags_)
{
    return zmq_msg_recv (msg_, s_, flags_);
}


int zmq_recv (void *s_, void *buf_, size_t len_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    zmq_msg_t msg;
    int rc = zmq_msg_init (&msg);
    errno_assert (rc == 0);

    const int nbytes = s_recvmsg (s, &msg, flags_);
    if (unlikely (nbytes < 0)) {
        const int err = errno;
        rc = zmq_msg_close (&msg);
        errno_assert (rc == 0);
        errno = err;
        return -1;
    }

    //  An oversized message is silently truncated.
    const size_t to_copy = size_t (nbytes) < len_ ? size_t (nbytes) : len_;

    //  We explicitly allow a null buffer argument if len is zero
    if (to_copy) {
        assert (buf_);
        memcpy (buf_, zmq_msg_data (&msg), to_copy);
    }
    rc = zmq_msg_close (&msg);
    errno_assert (rc == 0);

    return nbytes;
}

// Receive a multi-part message
//
// Receives up to *count_ parts of a multi-part message.
// Sets *count_ to the actual number of parts read.
// ZMQ_RCVMORE is set to indicate if a complete multi-part message was read.
// Returns number of message parts read, or -1 on error.
//
// Note: even if -1 is returned, some parts of the message
// may have been read. Therefore the client must consult
// *count_ to retrieve message parts successfully read,
// even if -1 is returned.
//
// The iov_base* buffers of each iovec *a_ filled in by this
// function may be freed using free().
// TODO: this function has no man page
//
int zmq_recviov (void *s_, iovec *a_, size_t *count_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    if (unlikely (!count_ || *count_ <= 0 || !a_)) {
        errno = EINVAL;
        return -1;
    }

    const size_t count = *count_;
    int nread = 0;
    bool recvmore = true;

    *count_ = 0;

    for (size_t i = 0; recvmore && i < count; ++i) {
        zmq_msg_t msg;
        int rc = zmq_msg_init (&msg);
        errno_assert (rc == 0);

        const int nbytes = s_recvmsg (s, &msg, flags_);
        if (unlikely (nbytes < 0)) {
            const int err = errno;
            rc = zmq_msg_close (&msg);
            errno_assert (rc == 0);
            errno = err;
            nread = -1;
            break;
        }

        a_[i].iov_len = zmq_msg_size (&msg);
        a_[i].iov_base = static_cast<char *> (malloc (a_[i].iov_len));
        if (unlikely (!a_[i].iov_base)) {
            errno = ENOMEM;
            return -1;
        }
        memcpy (a_[i].iov_base, static_cast<char *> (zmq_msg_data (&msg)),
                a_[i].iov_len);
        // Assume zmq_socket ZMQ_RVCMORE is properly set.
        const zmq::msg_t *p_msg = reinterpret_cast<const zmq::msg_t *> (&msg);
        recvmore = p_msg->flags () & zmq::msg_t::more;
        rc = zmq_msg_close (&msg);
        errno_assert (rc == 0);
        ++*count_;
        ++nread;
    }
    return nread;
}

// Message manipulators.

int zmq_msg_init (zmq_msg_t *msg_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->init ();
}

int zmq_msg_init_size (zmq_msg_t *msg_, size_t size_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->init_size (size_);
}

int zmq_msg_init_buffer (zmq_msg_t *msg_, const void *buf_, size_t size_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->init_buffer (buf_, size_);
}

int zmq_msg_init_data (
  zmq_msg_t *msg_, void *data_, size_t size_, zmq_free_fn *ffn_, void *hint_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))
      ->init_data (data_, size_, ffn_, hint_);
}

int zmq_msg_init_external_storage (zmq_msg_t *msg_,
                                   zmq_msg_content_t *content_,
                                   void *data_,
                                   size_t size_,
                                   zmq_free_fn *ffn_,
                                   void *hint_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))
      ->init_external_storage (
        reinterpret_cast<zmq::msg_t::content_t *> (content_), data_, size_,
        ffn_, hint_);
}


int zmq_msg_send (zmq_msg_t *msg_, void *s_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s_sendmsg (s, msg_, flags_);
}

int zmq_msg_recv (zmq_msg_t *msg_, void *s_, int flags_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s_recvmsg (s, msg_, flags_);
}

int zmq_msg_close (zmq_msg_t *msg_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->close ();
}

int zmq_msg_move (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    return (reinterpret_cast<zmq::msg_t *> (dest_))
      ->move (*reinterpret_cast<zmq::msg_t *> (src_));
}

int zmq_msg_copy (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    return (reinterpret_cast<zmq::msg_t *> (dest_))
      ->copy (*reinterpret_cast<zmq::msg_t *> (src_));
}

void *zmq_msg_data (zmq_msg_t *msg_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->data ();
}

size_t zmq_msg_size (const zmq_msg_t *msg_)
{
    return ((zmq::msg_t *) msg_)->size ();
}

int zmq_msg_more (const zmq_msg_t *msg_)
{
    return zmq_msg_get (msg_, ZMQ_MORE);
}

int zmq_msg_get (const zmq_msg_t *msg_, int property_)
{
    const char *fd_string;

    switch (property_) {
        case ZMQ_MORE:
            return (((zmq::msg_t *) msg_)->flags () & zmq::msg_t::more) ? 1 : 0;
        case ZMQ_SRCFD:
            fd_string = zmq_msg_gets (msg_, "__fd");
            if (fd_string == NULL)
                return -1;

            return atoi (fd_string);
        case ZMQ_SHARED:
            return (((zmq::msg_t *) msg_)->is_cmsg ())
                       || (((zmq::msg_t *) msg_)->flags () & zmq::msg_t::shared)
                     ? 1
                     : 0;
        default:
            errno = EINVAL;
            return -1;
    }
}

int zmq_msg_set (zmq_msg_t *, int, int)
{
    //  No properties supported at present
    errno = EINVAL;
    return -1;
}

int zmq_msg_set_routing_id (zmq_msg_t *msg_, uint32_t routing_id_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))
      ->set_routing_id (routing_id_);
}

uint32_t zmq_msg_routing_id (zmq_msg_t *msg_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->get_routing_id ();
}

int zmq_msg_set_group (zmq_msg_t *msg_, const char *group_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->set_group (group_);
}

const char *zmq_msg_group (zmq_msg_t *msg_)
{
    return (reinterpret_cast<zmq::msg_t *> (msg_))->group ();
}

//  Get message metadata string

const char *zmq_msg_gets (const zmq_msg_t *msg_, const char *property_)
{
    const zmq::metadata_t *metadata =
      reinterpret_cast<const zmq::msg_t *> (msg_)->metadata ();
    const char *value = NULL;
    if (metadata)
        value = metadata->get (std::string (property_));
    if (value)
        return value;

    errno = EINVAL;
    return NULL;
}

// Polling.

#if defined ZMQ_HAVE_POLLER
static int zmq_poller_poll (zmq_pollitem_t *items_, int nitems_, long timeout_)
{
    // implement zmq_poll on top of zmq_poller
    int rc;
    zmq_poller_event_t *events;
    zmq::socket_poller_t poller;
    events = new (std::nothrow) zmq_poller_event_t[nitems_];
    alloc_assert (events);

    bool repeat_items = false;
    //  Register sockets with poller
    for (int i = 0; i < nitems_; i++) {
        items_[i].revents = 0;

        bool modify = false;
        short e = items_[i].events;
        if (items_[i].socket) {
            //  Poll item is a 0MQ socket.
            for (int j = 0; j < i; ++j) {
                // Check for repeat entries
                if (items_[j].socket == items_[i].socket) {
                    repeat_items = true;
                    modify = true;
                    e |= items_[j].events;
                }
            }
            if (modify) {
                rc = zmq_poller_modify (&poller, items_[i].socket, e);
            } else {
                rc = zmq_poller_add (&poller, items_[i].socket, NULL, e);
            }
            if (rc < 0) {
                delete[] events;
                return rc;
            }
        } else {
            //  Poll item is a raw file descriptor.
            for (int j = 0; j < i; ++j) {
                // Check for repeat entries
                if (!items_[j].socket && items_[j].fd == items_[i].fd) {
                    repeat_items = true;
                    modify = true;
                    e |= items_[j].events;
                }
            }
            if (modify) {
                rc = zmq_poller_modify_fd (&poller, items_[i].fd, e);
            } else {
                rc = zmq_poller_add_fd (&poller, items_[i].fd, NULL, e);
            }
            if (rc < 0) {
                delete[] events;
                return rc;
            }
        }
    }

    //  Wait for events
    rc = zmq_poller_wait_all (&poller, events, nitems_, timeout_);
    if (rc < 0) {
        delete[] events;
        if (zmq_errno () == EAGAIN) {
            return 0;
        }
        return rc;
    }

    //  Transform poller events into zmq_pollitem events.
    //  items_ contains all items, while events only contains fired events.
    //  If no sockets are repeated (likely), the two are still co-ordered, so step through the items
    //  checking for matches only on the first event.
    //  If there are repeat items, they cannot be assumed to be co-ordered,
    //  so each pollitem must check fired events from the beginning.
    int j_start = 0, found_events = rc;
    for (int i = 0; i < nitems_; i++) {
        for (int j = j_start; j < found_events; ++j) {
            if ((items_[i].socket && items_[i].socket == events[j].socket)
                || (!(items_[i].socket || events[j].socket)
                    && items_[i].fd == events[j].fd)) {
                items_[i].revents = events[j].events & items_[i].events;
                if (!repeat_items) {
                    // no repeats, we can ignore events we've already seen
                    j_start++;
                }
                break;
            }
            if (!repeat_items) {
                // no repeats, never have to look at j > j_start
                break;
            }
        }
    }

    //  Cleanup
    delete[] events;
    return rc;
}
#endif // ZMQ_HAVE_POLLER

int zmq_poll (zmq_pollitem_t *items_, int nitems_, long timeout_)
{
#if defined ZMQ_HAVE_POLLER
    // if poller is present, use that if there is at least 1 thread-safe socket,
    // otherwise fall back to the previous implementation as it's faster.
    for (int i = 0; i != nitems_; i++) {
        if (items_[i].socket) {
            zmq::socket_base_t *s = as_socket_base_t (items_[i].socket);
            if (s) {
                if (s->is_thread_safe ())
                    return zmq_poller_poll (items_, nitems_, timeout_);
            } else {
                //as_socket_base_t returned NULL : socket is invalid
                return -1;
            }
        }
    }
#endif // ZMQ_HAVE_POLLER
#if defined ZMQ_POLL_BASED_ON_POLL || defined ZMQ_POLL_BASED_ON_SELECT
    if (unlikely (nitems_ < 0)) {
        errno = EINVAL;
        return -1;
    }
    if (unlikely (nitems_ == 0)) {
        if (timeout_ == 0)
            return 0;
#if defined ZMQ_HAVE_WINDOWS
        Sleep (timeout_ > 0 ? timeout_ : INFINITE);
        return 0;
#elif defined ZMQ_HAVE_VXWORKS
        struct timespec ns_;
        ns_.tv_sec = timeout_ / 1000;
        ns_.tv_nsec = timeout_ % 1000 * 1000000;
        return nanosleep (&ns_, 0);
#else
        return usleep (timeout_ * 1000);
#endif
    }
    if (!items_) {
        errno = EFAULT;
        return -1;
    }

    zmq::clock_t clock;
    uint64_t now = 0;
    uint64_t end = 0;
#if defined ZMQ_POLL_BASED_ON_POLL
    zmq::fast_vector_t<pollfd, ZMQ_POLLITEMS_DFLT> pollfds (nitems_);

    //  Build pollset for poll () system call.
    for (int i = 0; i != nitems_; i++) {
        //  If the poll item is a 0MQ socket, we poll on the file descriptor
        //  retrieved by the ZMQ_FD socket option.
        if (items_[i].socket) {
            size_t zmq_fd_size = sizeof (zmq::fd_t);
            if (zmq_getsockopt (items_[i].socket, ZMQ_FD, &pollfds[i].fd,
                                &zmq_fd_size)
                == -1) {
                return -1;
            }
            pollfds[i].events = items_[i].events ? POLLIN : 0;
        }
        //  Else, the poll item is a raw file descriptor. Just convert the
        //  events to normal POLLIN/POLLOUT for poll ().
        else {
            pollfds[i].fd = items_[i].fd;
            pollfds[i].events =
              (items_[i].events & ZMQ_POLLIN ? POLLIN : 0)
              | (items_[i].events & ZMQ_POLLOUT ? POLLOUT : 0)
              | (items_[i].events & ZMQ_POLLPRI ? POLLPRI : 0);
        }
    }
#else
    //  Ensure we do not attempt to select () on more than FD_SETSIZE
    //  file descriptors.
    //  TODO since this function is called by a client, we could return errno EINVAL/ENOMEM/... here
    zmq_assert (nitems_ <= FD_SETSIZE);

    zmq::optimized_fd_set_t pollset_in (nitems_);
    FD_ZERO (pollset_in.get ());
    zmq::optimized_fd_set_t pollset_out (nitems_);
    FD_ZERO (pollset_out.get ());
    zmq::optimized_fd_set_t pollset_err (nitems_);
    FD_ZERO (pollset_err.get ());

    zmq::fd_t maxfd = 0;

    //  Build the fd_sets for passing to select ().
    for (int i = 0; i != nitems_; i++) {
        //  If the poll item is a 0MQ socket we are interested in input on the
        //  notification file descriptor retrieved by the ZMQ_FD socket option.
        if (items_[i].socket) {
            size_t zmq_fd_size = sizeof (zmq::fd_t);
            zmq::fd_t notify_fd;
            if (zmq_getsockopt (items_[i].socket, ZMQ_FD, &notify_fd,
                                &zmq_fd_size)
                == -1)
                return -1;
            if (items_[i].events) {
                FD_SET (notify_fd, pollset_in.get ());
                if (maxfd < notify_fd)
                    maxfd = notify_fd;
            }
        }
        //  Else, the poll item is a raw file descriptor. Convert the poll item
        //  events to the appropriate fd_sets.
        else {
            if (items_[i].events & ZMQ_POLLIN)
                FD_SET (items_[i].fd, pollset_in.get ());
            if (items_[i].events & ZMQ_POLLOUT)
                FD_SET (items_[i].fd, pollset_out.get ());
            if (items_[i].events & ZMQ_POLLERR)
                FD_SET (items_[i].fd, pollset_err.get ());
            if (maxfd < items_[i].fd)
                maxfd = items_[i].fd;
        }
    }

    zmq::optimized_fd_set_t inset (nitems_);
    zmq::optimized_fd_set_t outset (nitems_);
    zmq::optimized_fd_set_t errset (nitems_);
#endif

    bool first_pass = true;
    int nevents = 0;

    while (true) {
#if defined ZMQ_POLL_BASED_ON_POLL

        //  Compute the timeout for the subsequent poll.
        const zmq::timeout_t timeout =
          zmq::compute_timeout (first_pass, timeout_, now, end);

        //  Wait for events.
        {
            const int rc = poll (&pollfds[0], nitems_, timeout);
            if (rc == -1 && errno == EINTR) {
                return -1;
            }
            errno_assert (rc >= 0);
        }
        //  Check for the events.
        for (int i = 0; i != nitems_; i++) {
            items_[i].revents = 0;

            //  The poll item is a 0MQ socket. Retrieve pending events
            //  using the ZMQ_EVENTS socket option.
            if (items_[i].socket) {
                size_t zmq_events_size = sizeof (uint32_t);
                uint32_t zmq_events;
                if (zmq_getsockopt (items_[i].socket, ZMQ_EVENTS, &zmq_events,
                                    &zmq_events_size)
                    == -1) {
                    return -1;
                }
                if ((items_[i].events & ZMQ_POLLOUT)
                    && (zmq_events & ZMQ_POLLOUT))
                    items_[i].revents |= ZMQ_POLLOUT;
                if ((items_[i].events & ZMQ_POLLIN)
                    && (zmq_events & ZMQ_POLLIN))
                    items_[i].revents |= ZMQ_POLLIN;
            }
            //  Else, the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            else {
                if (pollfds[i].revents & POLLIN)
                    items_[i].revents |= ZMQ_POLLIN;
                if (pollfds[i].revents & POLLOUT)
                    items_[i].revents |= ZMQ_POLLOUT;
                if (pollfds[i].revents & POLLPRI)
                    items_[i].revents |= ZMQ_POLLPRI;
                if (pollfds[i].revents & ~(POLLIN | POLLOUT | POLLPRI))
                    items_[i].revents |= ZMQ_POLLERR;
            }

            if (items_[i].revents)
                nevents++;
        }

#else

        //  Compute the timeout for the subsequent poll.
        timeval timeout;
        timeval *ptimeout;
        if (first_pass) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            ptimeout = &timeout;
        } else if (timeout_ < 0)
            ptimeout = NULL;
        else {
            timeout.tv_sec = static_cast<long> ((end - now) / 1000);
            timeout.tv_usec = static_cast<long> ((end - now) % 1000 * 1000);
            ptimeout = &timeout;
        }

        //  Wait for events. Ignore interrupts if there's infinite timeout.
        while (true) {
            memcpy (inset.get (), pollset_in.get (),
                    zmq::valid_pollset_bytes (*pollset_in.get ()));
            memcpy (outset.get (), pollset_out.get (),
                    zmq::valid_pollset_bytes (*pollset_out.get ()));
            memcpy (errset.get (), pollset_err.get (),
                    zmq::valid_pollset_bytes (*pollset_err.get ()));
#if defined ZMQ_HAVE_WINDOWS
            int rc =
              select (0, inset.get (), outset.get (), errset.get (), ptimeout);
            if (unlikely (rc == SOCKET_ERROR)) {
                errno = zmq::wsa_error_to_errno (WSAGetLastError ());
                wsa_assert (errno == ENOTSOCK);
                return -1;
            }
#else
            int rc = select (maxfd + 1, inset.get (), outset.get (),
                             errset.get (), ptimeout);
            if (unlikely (rc == -1)) {
                errno_assert (errno == EINTR || errno == EBADF);
                return -1;
            }
#endif
            break;
        }

        //  Check for the events.
        for (int i = 0; i != nitems_; i++) {
            items_[i].revents = 0;

            //  The poll item is a 0MQ socket. Retrieve pending events
            //  using the ZMQ_EVENTS socket option.
            if (items_[i].socket) {
                size_t zmq_events_size = sizeof (uint32_t);
                uint32_t zmq_events;
                if (zmq_getsockopt (items_[i].socket, ZMQ_EVENTS, &zmq_events,
                                    &zmq_events_size)
                    == -1)
                    return -1;
                if ((items_[i].events & ZMQ_POLLOUT)
                    && (zmq_events & ZMQ_POLLOUT))
                    items_[i].revents |= ZMQ_POLLOUT;
                if ((items_[i].events & ZMQ_POLLIN)
                    && (zmq_events & ZMQ_POLLIN))
                    items_[i].revents |= ZMQ_POLLIN;
            }
            //  Else, the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            else {
                if (FD_ISSET (items_[i].fd, inset.get ()))
                    items_[i].revents |= ZMQ_POLLIN;
                if (FD_ISSET (items_[i].fd, outset.get ()))
                    items_[i].revents |= ZMQ_POLLOUT;
                if (FD_ISSET (items_[i].fd, errset.get ()))
                    items_[i].revents |= ZMQ_POLLERR;
            }

            if (items_[i].revents)
                nevents++;
        }
#endif

        //  If timeout is zero, exit immediately whether there are events or not.
        if (timeout_ == 0)
            break;

        //  If there are events to return, we can exit immediately.
        if (nevents)
            break;

        //  At this point we are meant to wait for events but there are none.
        //  If timeout is infinite we can just loop until we get some events.
        if (timeout_ < 0) {
            if (first_pass)
                first_pass = false;
            continue;
        }

        //  The timeout is finite and there are no events. In the first pass
        //  we get a timestamp of when the polling have begun. (We assume that
        //  first pass have taken negligible time). We also compute the time
        //  when the polling should time out.
        if (first_pass) {
            now = clock.now_ms ();
            end = now + timeout_;
            if (now == end)
                break;
            first_pass = false;
            continue;
        }

        //  Find out whether timeout have expired.
        now = clock.now_ms ();
        if (now >= end)
            break;
    }

    return nevents;
#else
    //  Exotic platforms that support neither poll() nor select().
    errno = ENOTSUP;
    return -1;
#endif
}

#ifdef ZMQ_HAVE_PPOLL
// return values of 0 or -1 should be returned from zmq_poll; return value 1 means items passed checks
int zmq_poll_check_items_ (zmq_pollitem_t *items_, int nitems_, long timeout_)
{
    if (unlikely (nitems_ < 0)) {
        errno = EINVAL;
        return -1;
    }
    if (unlikely (nitems_ == 0)) {
        if (timeout_ == 0)
            return 0;
#if defined ZMQ_HAVE_WINDOWS
        Sleep (timeout_ > 0 ? timeout_ : INFINITE);
        return 0;
#elif defined ZMQ_HAVE_VXWORKS
        struct timespec ns_;
        ns_.tv_sec = timeout_ / 1000;
        ns_.tv_nsec = timeout_ % 1000 * 1000000;
        return nanosleep (&ns_, 0);
#else
        return usleep (timeout_ * 1000);
#endif
    }
    if (!items_) {
        errno = EFAULT;
        return -1;
    }
    return 1;
}

struct zmq_poll_select_fds_t_
{
    explicit zmq_poll_select_fds_t_ (int nitems_) :
        pollset_in (nitems_),
        pollset_out (nitems_),
        pollset_err (nitems_),
        inset (nitems_),
        outset (nitems_),
        errset (nitems_),
        maxfd (0)
    {
        FD_ZERO (pollset_in.get ());
        FD_ZERO (pollset_out.get ());
        FD_ZERO (pollset_err.get ());
    }

    zmq::optimized_fd_set_t pollset_in;
    zmq::optimized_fd_set_t pollset_out;
    zmq::optimized_fd_set_t pollset_err;
    zmq::optimized_fd_set_t inset;
    zmq::optimized_fd_set_t outset;
    zmq::optimized_fd_set_t errset;
    zmq::fd_t maxfd;
};

zmq_poll_select_fds_t_
zmq_poll_build_select_fds_ (zmq_pollitem_t *items_, int nitems_, int &rc)
{
    //  Ensure we do not attempt to select () on more than FD_SETSIZE
    //  file descriptors.
    //  TODO since this function is called by a client, we could return errno EINVAL/ENOMEM/... here
    zmq_assert (nitems_ <= FD_SETSIZE);

    zmq_poll_select_fds_t_ fds (nitems_);

    //  Build the fd_sets for passing to select ().
    for (int i = 0; i != nitems_; i++) {
        //  If the poll item is a 0MQ socket we are interested in input on the
        //  notification file descriptor retrieved by the ZMQ_FD socket option.
        if (items_[i].socket) {
            size_t zmq_fd_size = sizeof (zmq::fd_t);
            zmq::fd_t notify_fd;
            if (zmq_getsockopt (items_[i].socket, ZMQ_FD, &notify_fd,
                                &zmq_fd_size)
                == -1) {
                rc = -1;
                return fds;
            }
            if (items_[i].events) {
                FD_SET (notify_fd, fds.pollset_in.get ());
                if (fds.maxfd < notify_fd)
                    fds.maxfd = notify_fd;
            }
        }
        //  Else, the poll item is a raw file descriptor. Convert the poll item
        //  events to the appropriate fd_sets.
        else {
            if (items_[i].events & ZMQ_POLLIN)
                FD_SET (items_[i].fd, fds.pollset_in.get ());
            if (items_[i].events & ZMQ_POLLOUT)
                FD_SET (items_[i].fd, fds.pollset_out.get ());
            if (items_[i].events & ZMQ_POLLERR)
                FD_SET (items_[i].fd, fds.pollset_err.get ());
            if (fds.maxfd < items_[i].fd)
                fds.maxfd = items_[i].fd;
        }
    }

    rc = 0;
    return fds;
}

timeval *zmq_poll_select_set_timeout_ (
  long timeout_, bool first_pass, uint64_t now, uint64_t end, timeval &timeout)
{
    timeval *ptimeout;
    if (first_pass) {
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        ptimeout = &timeout;
    } else if (timeout_ < 0)
        ptimeout = NULL;
    else {
        timeout.tv_sec = static_cast<long> ((end - now) / 1000);
        timeout.tv_usec = static_cast<long> ((end - now) % 1000 * 1000);
        ptimeout = &timeout;
    }
    return ptimeout;
}

timespec *zmq_poll_select_set_timeout_ (
  long timeout_, bool first_pass, uint64_t now, uint64_t end, timespec &timeout)
{
    timespec *ptimeout;
    if (first_pass) {
        timeout.tv_sec = 0;
        timeout.tv_nsec = 0;
        ptimeout = &timeout;
    } else if (timeout_ < 0)
        ptimeout = NULL;
    else {
        timeout.tv_sec = static_cast<long> ((end - now) / 1000);
        timeout.tv_nsec = static_cast<long> ((end - now) % 1000 * 1000000);
        ptimeout = &timeout;
    }
    return ptimeout;
}

int zmq_poll_select_check_events_ (zmq_pollitem_t *items_,
                                   int nitems_,
                                   zmq_poll_select_fds_t_ &fds,
                                   int &nevents)
{
    //  Check for the events.
    for (int i = 0; i != nitems_; i++) {
        items_[i].revents = 0;

        //  The poll item is a 0MQ socket. Retrieve pending events
        //  using the ZMQ_EVENTS socket option.
        if (items_[i].socket) {
            size_t zmq_events_size = sizeof (uint32_t);
            uint32_t zmq_events;
            if (zmq_getsockopt (items_[i].socket, ZMQ_EVENTS, &zmq_events,
                                &zmq_events_size)
                == -1)
                return -1;
            if ((items_[i].events & ZMQ_POLLOUT) && (zmq_events & ZMQ_POLLOUT))
                items_[i].revents |= ZMQ_POLLOUT;
            if ((items_[i].events & ZMQ_POLLIN) && (zmq_events & ZMQ_POLLIN))
                items_[i].revents |= ZMQ_POLLIN;
        }
        //  Else, the poll item is a raw file descriptor, simply convert
        //  the events to zmq_pollitem_t-style format.
        else {
            if (FD_ISSET (items_[i].fd, fds.inset.get ()))
                items_[i].revents |= ZMQ_POLLIN;
            if (FD_ISSET (items_[i].fd, fds.outset.get ()))
                items_[i].revents |= ZMQ_POLLOUT;
            if (FD_ISSET (items_[i].fd, fds.errset.get ()))
                items_[i].revents |= ZMQ_POLLERR;
        }

        if (items_[i].revents)
            nevents++;
    }

    return 0;
}

bool zmq_poll_must_break_loop_ (long timeout_,
                                int nevents,
                                bool &first_pass,
                                zmq::clock_t &clock,
                                uint64_t &now,
                                uint64_t &end)
{
    //  If timeout is zero, exit immediately whether there are events or not.
    if (timeout_ == 0)
        return true;

    //  If there are events to return, we can exit immediately.
    if (nevents)
        return true;

    //  At this point we are meant to wait for events but there are none.
    //  If timeout is infinite we can just loop until we get some events.
    if (timeout_ < 0) {
        if (first_pass)
            first_pass = false;
        return false;
    }

    //  The timeout is finite and there are no events. In the first pass
    //  we get a timestamp of when the polling have begun. (We assume that
    //  first pass have taken negligible time). We also compute the time
    //  when the polling should time out.
    if (first_pass) {
        now = clock.now_ms ();
        end = now + timeout_;
        if (now == end)
            return true;
        first_pass = false;
        return false;
    }

    //  Find out whether timeout have expired.
    now = clock.now_ms ();
    if (now >= end)
        return true;

    // finally, in all other cases, we just continue
    return false;
}
#endif // ZMQ_HAVE_PPOLL

#if !defined _WIN32
int zmq_ppoll (zmq_pollitem_t *items_,
               int nitems_,
               long timeout_,
               const sigset_t *sigmask_)
#else
// Windows has no sigset_t
int zmq_ppoll (zmq_pollitem_t *items_,
               int nitems_,
               long timeout_,
               const void *sigmask_)
#endif
{
#ifdef ZMQ_HAVE_PPOLL
    int rc = zmq_poll_check_items_ (items_, nitems_, timeout_);
    if (rc <= 0) {
        return rc;
    }

    zmq::clock_t clock;
    uint64_t now = 0;
    uint64_t end = 0;
    zmq_poll_select_fds_t_ fds =
      zmq_poll_build_select_fds_ (items_, nitems_, rc);
    if (rc == -1) {
        return -1;
    }

    bool first_pass = true;
    int nevents = 0;

    while (true) {
        //  Compute the timeout for the subsequent poll.
        timespec timeout;
        timespec *ptimeout = zmq_poll_select_set_timeout_ (timeout_, first_pass,
                                                           now, end, timeout);

        //  Wait for events. Ignore interrupts if there's infinite timeout.
        while (true) {
            memcpy (fds.inset.get (), fds.pollset_in.get (),
                    zmq::valid_pollset_bytes (*fds.pollset_in.get ()));
            memcpy (fds.outset.get (), fds.pollset_out.get (),
                    zmq::valid_pollset_bytes (*fds.pollset_out.get ()));
            memcpy (fds.errset.get (), fds.pollset_err.get (),
                    zmq::valid_pollset_bytes (*fds.pollset_err.get ()));
            int rc =
              pselect (fds.maxfd + 1, fds.inset.get (), fds.outset.get (),
                       fds.errset.get (), ptimeout, sigmask_);
            if (unlikely (rc == -1)) {
                errno_assert (errno == EINTR || errno == EBADF);
                return -1;
            }
            break;
        }

        rc = zmq_poll_select_check_events_ (items_, nitems_, fds, nevents);
        if (rc < 0) {
            return rc;
        }

        if (zmq_poll_must_break_loop_ (timeout_, nevents, first_pass, clock,
                                       now, end)) {
            break;
        }
    }

    return nevents;
#else
    errno = ENOTSUP;
    return -1;
#endif // ZMQ_HAVE_PPOLL
}

//  The poller functionality

void *zmq_poller_new (void)
{
    zmq::socket_poller_t *poller = new (std::nothrow) zmq::socket_poller_t;
    if (!poller) {
        errno = ENOMEM;
    }
    return poller;
}

int zmq_poller_destroy (void **poller_p_)
{
    if (poller_p_) {
        const zmq::socket_poller_t *const poller =
          static_cast<const zmq::socket_poller_t *> (*poller_p_);
        if (poller && poller->check_tag ()) {
            delete poller;
            *poller_p_ = NULL;
            return 0;
        }
    }
    errno = EFAULT;
    return -1;
}


static int check_poller (void *const poller_)
{
    if (!poller_
        || !(static_cast<zmq::socket_poller_t *> (poller_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return 0;
}

static int check_events (const short events_)
{
    if (events_ & ~(ZMQ_POLLIN | ZMQ_POLLOUT | ZMQ_POLLERR | ZMQ_POLLPRI)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int check_poller_registration_args (void *const poller_, void *const s_)
{
    if (-1 == check_poller (poller_))
        return -1;

    if (!s_ || !(static_cast<zmq::socket_base_t *> (s_))->check_tag ()) {
        errno = ENOTSOCK;
        return -1;
    }

    return 0;
}

static int check_poller_fd_registration_args (void *const poller_,
                                              const zmq::fd_t fd_)
{
    if (-1 == check_poller (poller_))
        return -1;

    if (fd_ == zmq::retired_fd) {
        errno = EBADF;
        return -1;
    }

    return 0;
}

int zmq_poller_size (void *poller_)
{
    if (-1 == check_poller (poller_))
        return -1;

    return (static_cast<zmq::socket_poller_t *> (poller_))->size ();
}

int zmq_poller_add (void *poller_, void *s_, void *user_data_, short events_)
{
    if (-1 == check_poller_registration_args (poller_, s_)
        || -1 == check_events (events_))
        return -1;

    zmq::socket_base_t *socket = static_cast<zmq::socket_base_t *> (s_);

    return (static_cast<zmq::socket_poller_t *> (poller_))
      ->add (socket, user_data_, events_);
}

int zmq_poller_add_fd (void *poller_,
                       zmq::fd_t fd_,
                       void *user_data_,
                       short events_)
{
    if (-1 == check_poller_fd_registration_args (poller_, fd_)
        || -1 == check_events (events_))
        return -1;

    return (static_cast<zmq::socket_poller_t *> (poller_))
      ->add_fd (fd_, user_data_, events_);
}


int zmq_poller_modify (void *poller_, void *s_, short events_)
{
    if (-1 == check_poller_registration_args (poller_, s_)
        || -1 == check_events (events_))
        return -1;

    const zmq::socket_base_t *const socket =
      static_cast<const zmq::socket_base_t *> (s_);

    return (static_cast<zmq::socket_poller_t *> (poller_))
      ->modify (socket, events_);
}

int zmq_poller_modify_fd (void *poller_, zmq::fd_t fd_, short events_)
{
    if (-1 == check_poller_fd_registration_args (poller_, fd_)
        || -1 == check_events (events_))
        return -1;

    return (static_cast<zmq::socket_poller_t *> (poller_))
      ->modify_fd (fd_, events_);
}

int zmq_poller_remove (void *poller_, void *s_)
{
    if (-1 == check_poller_registration_args (poller_, s_))
        return -1;

    zmq::socket_base_t *socket = static_cast<zmq::socket_base_t *> (s_);

    return (static_cast<zmq::socket_poller_t *> (poller_))->remove (socket);
}

int zmq_poller_remove_fd (void *poller_, zmq::fd_t fd_)
{
    if (-1 == check_poller_fd_registration_args (poller_, fd_))
        return -1;

    return (static_cast<zmq::socket_poller_t *> (poller_))->remove_fd (fd_);
}

int zmq_poller_wait (void *poller_, zmq_poller_event_t *event_, long timeout_)
{
    const int rc = zmq_poller_wait_all (poller_, event_, 1, timeout_);

    if (rc < 0 && event_) {
        event_->socket = NULL;
        event_->fd = zmq::retired_fd;
        event_->user_data = NULL;
        event_->events = 0;
    }
    // wait_all returns number of events, but we return 0 for any success
    return rc >= 0 ? 0 : rc;
}

int zmq_poller_wait_all (void *poller_,
                         zmq_poller_event_t *events_,
                         int n_events_,
                         long timeout_)
{
    if (-1 == check_poller (poller_))
        return -1;

    if (!events_) {
        errno = EFAULT;
        return -1;
    }
    if (n_events_ < 0) {
        errno = EINVAL;
        return -1;
    }

    const int rc =
      (static_cast<zmq::socket_poller_t *> (poller_))
        ->wait (reinterpret_cast<zmq::socket_poller_t::event_t *> (events_),
                n_events_, timeout_);

    return rc;
}

int zmq_poller_fd (void *poller_, zmq_fd_t *fd_)
{
    if (!poller_
        || !(static_cast<zmq::socket_poller_t *> (poller_)->check_tag ())) {
        errno = EFAULT;
        return -1;
    }
    return static_cast<zmq::socket_poller_t *> (poller_)->signaler_fd (fd_);
}

//  Peer-specific state

int zmq_socket_get_peer_state (void *s_,
                               const void *routing_id_,
                               size_t routing_id_size_)
{
    const zmq::socket_base_t *const s = as_socket_base_t (s_);
    if (!s)
        return -1;

    return s->get_peer_state (routing_id_, routing_id_size_);
}

//  Timers

void *zmq_timers_new (void)
{
    zmq::timers_t *timers = new (std::nothrow) zmq::timers_t;
    alloc_assert (timers);
    return timers;
}

int zmq_timers_destroy (void **timers_p_)
{
    void *timers = *timers_p_;
    if (!timers || !(static_cast<zmq::timers_t *> (timers))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }
    delete (static_cast<zmq::timers_t *> (timers));
    *timers_p_ = NULL;
    return 0;
}

int zmq_timers_add (void *timers_,
                    size_t interval_,
                    zmq_timer_fn handler_,
                    void *arg_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))
      ->add (interval_, handler_, arg_);
}

int zmq_timers_cancel (void *timers_, int timer_id_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))->cancel (timer_id_);
}

int zmq_timers_set_interval (void *timers_, int timer_id_, size_t interval_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))
      ->set_interval (timer_id_, interval_);
}

int zmq_timers_reset (void *timers_, int timer_id_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))->reset (timer_id_);
}

long zmq_timers_timeout (void *timers_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))->timeout ();
}

int zmq_timers_execute (void *timers_)
{
    if (!timers_ || !(static_cast<zmq::timers_t *> (timers_))->check_tag ()) {
        errno = EFAULT;
        return -1;
    }

    return (static_cast<zmq::timers_t *> (timers_))->execute ();
}

//  The proxy functionality

int zmq_proxy (void *frontend_, void *backend_, void *capture_)
{
    if (!frontend_ || !backend_) {
        errno = EFAULT;
        return -1;
    }
    // Runs zmq::proxy_steerable with a NULL control_.
    return zmq::proxy (static_cast<zmq::socket_base_t *> (frontend_),
                       static_cast<zmq::socket_base_t *> (backend_),
                       static_cast<zmq::socket_base_t *> (capture_));
}

int zmq_proxy_steerable (void *frontend_,
                         void *backend_,
                         void *capture_,
                         void *control_)
{
    if (!frontend_ || !backend_) {
        errno = EFAULT;
        return -1;
    }
    return zmq::proxy_steerable (static_cast<zmq::socket_base_t *> (frontend_),
                                 static_cast<zmq::socket_base_t *> (backend_),
                                 static_cast<zmq::socket_base_t *> (capture_),
                                 static_cast<zmq::socket_base_t *> (control_));
}

//  The deprecated device functionality

int zmq_device (int /* type */, void *frontend_, void *backend_)
{
    return zmq::proxy (static_cast<zmq::socket_base_t *> (frontend_),
                       static_cast<zmq::socket_base_t *> (backend_), NULL);
}

//  Probe library capabilities; for now, reports on transport and security

int zmq_has (const char *capability_)
{
#if defined(ZMQ_HAVE_IPC)
    if (strcmp (capability_, zmq::protocol_name::ipc) == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_OPENPGM)
    if (strcmp (capability_, zmq::protocol_name::pgm) == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_TIPC)
    if (strcmp (capability_, zmq::protocol_name::tipc) == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_NORM)
    if (strcmp (capability_, zmq::protocol_name::norm) == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_CURVE)
    if (strcmp (capability_, "curve") == 0)
        return true;
#endif
#if defined(HAVE_LIBGSSAPI_KRB5)
    if (strcmp (capability_, "gssapi") == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_VMCI)
    if (strcmp (capability_, zmq::protocol_name::vmci) == 0)
        return true;
#endif
#if defined(ZMQ_BUILD_DRAFT_API)
    if (strcmp (capability_, "draft") == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_WS)
    if (strcmp (capability_, "WS") == 0)
        return true;
#endif
#if defined(ZMQ_HAVE_WSS)
    if (strcmp (capability_, "WSS") == 0)
        return true;
#endif
    //  Whatever the application asked for, we don't have
    return false;
}

int zmq_socket_monitor_pipes_stats (void *s_)
{
    zmq::socket_base_t *s = as_socket_base_t (s_);
    if (!s)
        return -1;
    return s->query_pipes_stats ();
}
