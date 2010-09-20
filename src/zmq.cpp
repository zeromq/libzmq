/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "../include/zmq.h"
#include "../include/zmq_utils.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <new>

#include "forwarder.hpp"
#include "queue.hpp"
#include "streamer.hpp"
#include "socket_base.hpp"
#include "msg_content.hpp"
#include "platform.hpp"
#include "stdint.hpp"
#include "config.hpp"
#include "ctx.hpp"
#include "err.hpp"
#include "fd.hpp"

#if defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD
#include <poll.h>
#endif

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <sys/time.h>
#endif

#if defined ZMQ_HAVE_OPENPGM
#include <pgm/pgm.h>
#endif

void zmq_version (int *major_, int *minor_, int *patch_)
{
    *major_ = PACKAGE_VERSION_MAJOR;
    *minor_ = PACKAGE_VERSION_MINOR;
    *patch_ = PACKAGE_VERSION_PATCH;
}

const char *zmq_strerror (int errnum_)
{
    switch (errnum_) {
#if defined ZMQ_HAVE_WINDOWS
    case ENOTSUP:
        return "Not supported";
    case EPROTONOSUPPORT:
        return "Protocol not supported";
    case ENOBUFS:
        return "No buffer space available";
    case ENETDOWN:
        return "Network is down";
    case EADDRINUSE:
        return "Address in use";
    case EADDRNOTAVAIL:
        return "Address not available";
    case ECONNREFUSED:
        return "Connection refused";
    case EINPROGRESS:
        return "Operation in progress";
#endif
    case EFSM:
        return "Operation cannot be accomplished in current state";
    case ENOCOMPATPROTO:
        return "The protocol is not compatible with the socket type";
    case ETERM:
        return "Context was terminated";
    case EMTHREAD:
        return "No thread available";
    default:
#if defined _MSC_VER
#pragma warning (push)
#pragma warning (disable:4996)
#endif
        return strerror (errnum_);
#if defined _MSC_VER
#pragma warning (pop)
#endif
    }
}

int zmq_msg_init (zmq_msg_t *msg_)
{
    msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
    msg_->flags = 0;
    msg_->vsm_size = 0;
    return 0;
}

int zmq_msg_init_size (zmq_msg_t *msg_, size_t size_)
{
    if (size_ <= ZMQ_MAX_VSM_SIZE) {
        msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
        msg_->flags = 0;
        msg_->vsm_size = (uint8_t) size_;
    }
    else {
        msg_->content =
            (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t) + size_);
        if (!msg_->content) {
            errno = ENOMEM;
            return -1;
        }
        msg_->flags = 0;
        
        zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
        content->data = (void*) (content + 1);
        content->size = size_;
        content->ffn = NULL;
        content->hint = NULL;
        new (&content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq_msg_init_data (zmq_msg_t *msg_, void *data_, size_t size_,
    zmq_free_fn *ffn_, void *hint_)
{
    msg_->content = (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t));
    zmq_assert (msg_->content);
    msg_->flags = 0;
    zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
    content->data = data_;
    content->size = size_;
    content->ffn = ffn_;
    content->hint = hint_;
    new (&content->refcnt) zmq::atomic_counter_t ();
    return 0;
}

int zmq_msg_close (zmq_msg_t *msg_)
{
    //  For VSMs and delimiters there are no resources to free.
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER ||
          msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return 0;

    //  If the content is not shared, or if it is shared and the reference.
    //  count has dropped to zero, deallocate it.
    zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
    if (!(msg_->flags & ZMQ_MSG_SHARED) || !content->refcnt.sub (1)) {

        //  We used "placement new" operator to initialize the reference.
        //  counter so we call its destructor now.
        content->refcnt.~atomic_counter_t ();

        if (content->ffn)
            content->ffn (content->data, content->hint);
        free (content);
    }

    return 0;
}

int zmq_msg_move (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    zmq_msg_close (dest_);
    *dest_ = *src_;
    zmq_msg_init (src_);
    return 0;
}

int zmq_msg_copy (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    zmq_msg_close (dest_);

    //  VSMs and delimiters require no special handling.
    if (src_->content != (zmq::msg_content_t*) ZMQ_DELIMITER &&
          src_->content != (zmq::msg_content_t*) ZMQ_VSM) {

        //  One reference is added to shared messages. Non-shared messages
        //  are turned into shared messages and reference count is set to 2.
        zmq::msg_content_t *content = (zmq::msg_content_t*) src_->content;
        if (src_->flags & ZMQ_MSG_SHARED)
            content->refcnt.add (1);
        else {
            src_->flags |= ZMQ_MSG_SHARED;
            content->refcnt.set (2);
        }
    }

    *dest_ = *src_;
    return 0;
}

void *zmq_msg_data (zmq_msg_t *msg_)
{
    if (msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return msg_->vsm_data;
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER)
        return NULL;

    return ((zmq::msg_content_t*) msg_->content)->data;
}

size_t zmq_msg_size (zmq_msg_t *msg_)
{
    if (msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return msg_->vsm_size;
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER)
        return 0;

    return ((zmq::msg_content_t*) msg_->content)->size;
}

void *zmq_init (int io_threads_)
{
    if (io_threads_ < 0) {
        errno = EINVAL;
        return NULL;
    }

#if defined ZMQ_HAVE_OPENPGM
    //  Unfortunately, OpenPGM doesn't support refcounted init/shutdown, thus,
    //  let's fail if it was initialised beforehand.
    zmq_assert (!pgm_supported ());

    //  Init PGM transport. Ensure threading and timer are enabled. Find PGM
    //  protocol ID. Note that if you want to use gettimeofday and sleep for
    //  openPGM timing, set environment variables PGM_TIMER to "GTOD" and
    //  PGM_SLEEP to "USLEEP".
    GError *pgm_error = NULL;
    int rc = pgm_init (&pgm_error);
    if (rc != TRUE) {
        if (pgm_error->domain == PGM_IF_ERROR && (
              pgm_error->code == PGM_IF_ERROR_INVAL ||
              pgm_error->code == PGM_IF_ERROR_XDEV ||
              pgm_error->code == PGM_IF_ERROR_NODEV ||
              pgm_error->code == PGM_IF_ERROR_NOTUNIQ ||
              pgm_error->code == PGM_IF_ERROR_ADDRFAMILY ||
              pgm_error->code == PGM_IF_ERROR_FAMILY ||
              pgm_error->code == PGM_IF_ERROR_NODATA ||
              pgm_error->code == PGM_IF_ERROR_NONAME ||
              pgm_error->code == PGM_IF_ERROR_SERVICE)) {
            g_error_free (pgm_error);
            errno = EINVAL;
            return NULL;
        }
        zmq_assert (false);
    }
#endif

    //  Create 0MQ context.
    zmq::ctx_t *ctx = new (std::nothrow) zmq::ctx_t ((uint32_t) io_threads_);
    zmq_assert (ctx);
    return (void*) ctx;
}

int zmq_term (void *ctx_)
{
    if (!ctx_) {
        errno = EFAULT;
        return -1;
    }

    int rc = ((zmq::ctx_t*) ctx_)->terminate ();
    int en = errno;

#if defined ZMQ_HAVE_OPENPGM
    //  Shut down the OpenPGM library.
    if (pgm_shutdown () != TRUE)
        zmq_assert (false);
#endif

    errno = en;
    return rc;
}

void *zmq_socket (void *ctx_, int type_)
{
    if (!ctx_) {
        errno = EFAULT;
        return NULL;
    }
    return (void*) (((zmq::ctx_t*) ctx_)->create_socket (type_));
}

int zmq_close (void *s_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    ((zmq::socket_base_t*) s_)->close ();
    return 0;
}

int zmq_setsockopt (void *s_, int option_, const void *optval_,
    size_t optvallen_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->setsockopt (option_, optval_,
        optvallen_));
}

int zmq_getsockopt (void *s_, int option_, void *optval_, size_t *optvallen_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->getsockopt (option_, optval_,
        optvallen_));
}

int zmq_bind (void *s_, const char *addr_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->bind (addr_));
}

int zmq_connect (void *s_, const char *addr_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->connect (addr_));
}

int zmq_send (void *s_, zmq_msg_t *msg_, int flags_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->send (msg_, flags_));
}

int zmq_recv (void *s_, zmq_msg_t *msg_, int flags_)
{
    if (!s_) {
        errno = EFAULT;
        return -1;
    }
    return (((zmq::socket_base_t*) s_)->recv (msg_, flags_));
}

#if defined ZMQ_FORCE_SELECT
#define ZMQ_POLL_BASED_ON_SELECT
#elif defined ZMQ_FORCE_POLL
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS
#define ZMQ_POLL_BASED_ON_SELECT
#endif

int zmq_poll (zmq_pollitem_t *items_, int nitems_, long timeout_)
{
#if defined ZMQ_POLL_BASED_ON_POLL

    if (!items_) {
        errno = EFAULT;
        return -1;
    }

    pollfd *pollfds = (pollfd*) malloc (nitems_ * sizeof (pollfd));
    zmq_assert (pollfds);

    //  Build pollset for poll () system call.
    for (int i = 0; i != nitems_; i++) {

        //  If the poll item is a 0MQ socket, we poll on the file descriptor
        //  retrieved by the ZMQ_FD socket option.
        if (items_ [i].socket) {
            size_t zmq_fd_size = sizeof (zmq::fd_t);
            if (zmq_getsockopt (items_ [i].socket, ZMQ_FD, &pollfds [i].fd,
                &zmq_fd_size) == -1) {
                free (pollfds);
                return -1;
            }
            pollfds [i].events = items_ [i].events ? POLLIN : 0;
        }
        //  Else, the poll item is a raw file descriptor. Just convert the
        //  events to normal POLLIN/POLLOUT for poll ().
        else {
            pollfds [i].fd = items_ [i].fd;
            pollfds [i].events =
                (items_ [i].events & ZMQ_POLLIN ? POLLIN : 0) |
                (items_ [i].events & ZMQ_POLLOUT ? POLLOUT : 0);
        }
    }

    bool first_pass = true;
    int timeout = timeout_ > 0 ? timeout_ / 1000 : -1;
    int nevents = 0;

    while (true) {

        //  Wait for events.
        while (true) {
            int rc = poll (pollfds, nitems_, first_pass ? 0 : timeout);
            if (rc == -1 && errno == EINTR) {
                free (pollfds);
                return -1;
            }
            errno_assert (rc >= 0);
            break;
        }

        //  Check for the events.
        for (int i = 0; i != nitems_; i++) {

            items_ [i].revents = 0;

            //  The poll item is a 0MQ socket. Retrieve pending events
            //  using the ZMQ_EVENTS socket option.
            if (items_ [i].socket) {
                size_t zmq_events_size = sizeof (uint32_t);
                uint32_t zmq_events;
                if (zmq_getsockopt (items_ [i].socket, ZMQ_EVENTS, &zmq_events,
                    &zmq_events_size) == -1) {
                    free (pollfds);
                    return -1;
                }
                if ((items_ [i].events & ZMQ_POLLOUT) &&
                      (zmq_events & ZMQ_POLLOUT))
                    items_ [i].revents |= ZMQ_POLLOUT;
                if ((items_ [i].events & ZMQ_POLLIN) &&
                      (zmq_events & ZMQ_POLLIN))
                    items_ [i].revents |= ZMQ_POLLIN;
            }
            //  Else, the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            else {
                if (pollfds [i].revents & POLLIN)
                    items_ [i].revents |= ZMQ_POLLIN;
                if (pollfds [i].revents & POLLOUT)
                    items_ [i].revents |= ZMQ_POLLOUT;
                if (pollfds [i].revents & ~(POLLIN | POLLOUT))
                    items_ [i].revents |= ZMQ_POLLERR;
            }

            if (items_ [i].revents)
                nevents++;
        }

        //  If there are no events from the first pass (the one with no
        //  timout), do at least the second pass so that we wait.
        if (first_pass && nevents == 0 && timeout_ != 0) {
            first_pass = false;
            continue;
        }

        //  If timeout is set to infinite and we have to events to return
        //  we can restart the polling.
        if (timeout == -1 && nevents == 0)
            continue;

        //  TODO: if nevents is zero recompute timeout and loop
        //  if it is not yet reached.

        break;
    }

    free (pollfds);
    return nevents;

#elif defined ZMQ_POLL_BASED_ON_SELECT

    fd_set pollset_in;
    FD_ZERO (&pollset_in);
    fd_set pollset_out;
    FD_ZERO (&pollset_out);
    fd_set pollset_err;
    FD_ZERO (&pollset_err);

    zmq::fd_t maxfd = 0;

    //  Ensure we do not attempt to select () on more than FD_SETSIZE
    //  file descriptors.
    zmq_assert (nitems_ <= FD_SETSIZE);

    //  Build the fd_sets for passing to select ().
    for (int i = 0; i != nitems_; i++) {

        //  If the poll item is a 0MQ socket we are interested in input on the
        //  notification file descriptor retrieved by the ZMQ_FD socket option.
        if (items_ [i].socket) {
            size_t zmq_fd_size = sizeof (zmq::fd_t);
            zmq::fd_t notify_fd;
            if (zmq_getsockopt (items_ [i].socket, ZMQ_FD, &notify_fd,
                &zmq_fd_size) == -1)
                return -1;
            if (items_ [i].events) {
                FD_SET (notify_fd, &pollset_in);
                if (maxfd < notify_fd)
                    maxfd = notify_fd;
            }
        }
        //  Else, the poll item is a raw file descriptor. Convert the poll item
        //  events to the appropriate fd_sets.
        else {
            if (items_ [i].events & ZMQ_POLLIN)
                FD_SET (items_ [i].fd, &pollset_in);
            if (items_ [i].events & ZMQ_POLLOUT)
                FD_SET (items_ [i].fd, &pollset_out);
            if (items_ [i].events & ZMQ_POLLERR)
                FD_SET (items_ [i].fd, &pollset_err);
            if (maxfd < items_ [i].fd)
                maxfd = items_ [i].fd;
        }
    }

    bool first_pass = true;
    timeval zero_timeout = {0, 0};
    timeval timeout = {timeout_ / 1000000, timeout_ % 1000000};
    int nevents = 0;
    fd_set inset, outset, errset;

    while (true) {

        //  Wait for events. Ignore interrupts if there's infinite timeout.
        while (true) {
            memcpy (&inset, &pollset_in, sizeof (fd_set));
            memcpy (&outset, &pollset_out, sizeof (fd_set));
            memcpy (&errset, &pollset_err, sizeof (fd_set));
            int rc = select (maxfd + 1, &inset, &outset, &errset,
                first_pass ? &zero_timeout : (timeout_ < 0 ? NULL : &timeout));
#if defined ZMQ_HAVE_WINDOWS
            wsa_assert (rc != SOCKET_ERROR);
#else
            if (rc == -1 && errno == EINTR)
                return -1;
            errno_assert (rc >= 0);
#endif
            break;
        }

        //  Check for the events.
        for (int i = 0; i != nitems_; i++) {

            items_ [i].revents = 0;

            //  The poll item is a 0MQ socket. Retrieve pending events
            //  using the ZMQ_EVENTS socket option.
            if (items_ [i].socket) {
                size_t zmq_fd_size = sizeof (zmq::fd_t);
                zmq::fd_t notify_fd;
                if (zmq_getsockopt (items_ [i].socket, ZMQ_FD, &notify_fd,
                      &zmq_fd_size) == -1)
                    return -1;
                if (FD_ISSET (notify_fd, &inset)) {
                    size_t zmq_events_size = sizeof (uint32_t);
                    uint32_t zmq_events;
                    if (zmq_getsockopt (items_ [i].socket, ZMQ_EVENTS, &zmq_events,
                          &zmq_events_size) == -1)
                        return -1;
                    if ((items_ [i].events & ZMQ_POLLOUT) &&
                          (zmq_events & ZMQ_POLLOUT))
                        items_ [i].revents |= ZMQ_POLLOUT;
                    if ((items_ [i].events & ZMQ_POLLIN) &&
                          (zmq_events & ZMQ_POLLIN))
                        items_ [i].revents |= ZMQ_POLLIN;
                }
            }
            //  Else, the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            else {
                if (FD_ISSET (items_ [i].fd, &inset))
                    items_ [i].revents |= ZMQ_POLLIN;
                if (FD_ISSET (items_ [i].fd, &outset))
                    items_ [i].revents |= ZMQ_POLLOUT;
                if (FD_ISSET (items_ [i].fd, &errset))
                    items_ [i].revents |= ZMQ_POLLERR;
            }

            if (items_ [i].revents)
                nevents++;
        }

        //  If there are no events from the first pass (the one with no
        //  timout), do at least the second pass so that we wait.
        if (first_pass && nevents == 0 && timeout_ != 0) {
            first_pass = false;
            continue;
        }

        //  If timeout is set to infinite and we have to events to return
        //  we can restart the polling.
        if (timeout_ < 0 && nevents == 0)
            continue;

        //  TODO: if nevents is zero recompute timeout and loop
        //  if it is not yet reached.

        break;
    }

    return nevents;

#else
    //  Exotic platforms that support neither poll() nor select().
    errno = ENOTSUP;
    return -1;
#endif
}

#if defined ZMQ_POLL_BASED_ON_SELECT
#undef ZMQ_POLL_BASED_ON_SELECT
#endif
#if defined ZMQ_POLL_BASED_ON_POLL
#undef ZMQ_POLL_BASED_ON_POLL
#endif

int zmq_errno ()
{
    return errno;
}

int zmq_device (int device_, void *insocket_, void *outsocket_)
{
    if (!insocket_ || !outsocket_) {
        errno = EFAULT;
        return -1;
    }
    switch (device_) {
    case ZMQ_FORWARDER:
        return zmq::forwarder ((zmq::socket_base_t*) insocket_,
            (zmq::socket_base_t*) outsocket_);
    case ZMQ_QUEUE:
        return zmq::queue ((zmq::socket_base_t*) insocket_,
            (zmq::socket_base_t*) outsocket_);
    case ZMQ_STREAMER:
        return zmq::streamer ((zmq::socket_base_t*) insocket_,
            (zmq::socket_base_t*) outsocket_);
    default:
        return EINVAL;
    }
}

////////////////////////////////////////////////////////////////////////////////
//  0MQ utils - to be used by perf tests
////////////////////////////////////////////////////////////////////////////////

#if defined ZMQ_HAVE_WINDOWS

static uint64_t now ()
{    
    //  Get the high resolution counter's accuracy.
    LARGE_INTEGER ticksPerSecond;
    QueryPerformanceFrequency (&ticksPerSecond);

    //  What time is it?
    LARGE_INTEGER tick;
    QueryPerformanceCounter (&tick);

    //  Convert the tick number into the number of seconds
    //  since the system was started.
    double ticks_div = (double) (ticksPerSecond.QuadPart / 1000000);     
    return (uint64_t) (tick.QuadPart / ticks_div);
}

void zmq_sleep (int seconds_)
{
    Sleep (seconds_ * 1000);
}

#else

static uint64_t now ()
{
    struct timeval tv;
    int rc;

    rc = gettimeofday (&tv, NULL);
    assert (rc == 0);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

void zmq_sleep (int seconds_)
{
    sleep (seconds_);
}

#endif

void *zmq_stopwatch_start ()
{
    uint64_t *watch = (uint64_t*) malloc (sizeof (uint64_t));
    assert (watch);
    *watch = now ();
    return (void*) watch;
}

unsigned long zmq_stopwatch_stop (void *watch_)
{
    uint64_t end = now ();
    uint64_t start = *(uint64_t*) watch_;
    free (watch_);
    return (unsigned long) (end - start);
}

