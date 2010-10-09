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
#include "app_thread.hpp"
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
    *major_ = ZMQ_VERSION_MAJOR;
    *minor_ = ZMQ_VERSION_MINOR;
    *patch_ = ZMQ_VERSION_PATCH;
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
    case EMTHREAD:
        return "Number of preallocated application threads exceeded";
    case EFSM:
        return "Operation cannot be accomplished in current state";
    case ENOCOMPATPROTO:
        return "The protocol is not compatible with the socket type";
    case ETERM:
        return "Context was terminated";
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

    int rc = ((zmq::ctx_t*) ctx_)->term ();
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

int zmq_poll (zmq_pollitem_t *items_, int nitems_, long timeout_)
{
#if defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD

    if (!items_) {
        errno = EFAULT;
        return -1;
    }
    pollfd *pollfds = (pollfd*) malloc (nitems_ * sizeof (pollfd));
    zmq_assert (pollfds);
    int npollfds = 0;
    int nsockets = 0;

    zmq::app_thread_t *app_thread = NULL;

    for (int i = 0; i != nitems_; i++) {

        //  0MQ sockets.
        if (items_ [i].socket) {

            //  Get the app_thread the socket is living in. If there are two
            //  sockets in the same pollset with different app threads, fail.
            zmq::socket_base_t *s = (zmq::socket_base_t*) items_ [i].socket;
            if (app_thread) {
                if (app_thread != s->get_thread ()) {
                    free (pollfds);
                    errno = EFAULT;
                    return -1;
                }
            }
            else
                app_thread = s->get_thread ();

            nsockets++;
            continue;
        }

        //  Raw file descriptors.
        pollfds [npollfds].fd = items_ [i].fd;
        pollfds [npollfds].events =
            (items_ [i].events & ZMQ_POLLIN ? POLLIN : 0) |
            (items_ [i].events & ZMQ_POLLOUT ? POLLOUT : 0);
        npollfds++;
    }

    //  If there's at least one 0MQ socket in the pollset we have to poll
    //  for 0MQ commands. If ZMQ_POLL was not set, fail.
    if (nsockets) {
        pollfds [npollfds].fd = app_thread->get_signaler ()->get_fd ();
        if (pollfds [npollfds].fd == zmq::retired_fd) {
            free (pollfds);
            errno = ENOTSUP;
            return -1;
        }
        pollfds [npollfds].events = POLLIN;
        npollfds++;
    }

    //  First iteration just check for events, don't block. Waiting would
    //  prevent exiting on any events that may already been signaled on
    //  0MQ sockets.
    int rc = poll (pollfds, npollfds, 0);
    if (rc == -1 && errno == EINTR && timeout_ >= 0) {
        free (pollfds);
        return 0;
    }
    errno_assert (rc >= 0 || (rc == -1 && errno == EINTR));

    int timeout = timeout_ > 0 ? timeout_ / 1000 : -1;
    int nevents = 0;

    while (true) {

        //  Process 0MQ commands if needed.
        if (nsockets && pollfds [npollfds -1].revents & POLLIN)
            if (!app_thread->process_commands (false, false)) {
                free (pollfds);
                errno = ETERM;
                return -1;
            }

        //  Check for the events.
        int pollfd_pos = 0;
        for (int i = 0; i != nitems_; i++) {

            //  If the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            if (!items_ [i].socket) {
                items_ [i].revents = 0;
                if (pollfds [pollfd_pos].revents & POLLIN)
                    items_ [i].revents |= ZMQ_POLLIN;
                if (pollfds [pollfd_pos].revents & POLLOUT)
                    items_ [i].revents |= ZMQ_POLLOUT;
                if (pollfds [pollfd_pos].revents & ~(POLLIN | POLLOUT))
                    items_ [i].revents |= ZMQ_POLLERR;

                if (items_ [i].revents)
                    nevents++;
                pollfd_pos++;
                continue;
            }

            //  The poll item is a 0MQ socket.
            zmq::socket_base_t *s = (zmq::socket_base_t*) items_ [i].socket;
            items_ [i].revents = 0;
            if ((items_ [i].events & ZMQ_POLLOUT) && s->has_out ())
                items_ [i].revents |= ZMQ_POLLOUT;
            if ((items_ [i].events & ZMQ_POLLIN) && s->has_in ())
                items_ [i].revents |= ZMQ_POLLIN;
            if (items_ [i].revents)
                nevents++;
        }

        //  If there's at least one event, or if we are asked not to block,
        //  return immediately.
        if (nevents || !timeout_)
            break;

        //  Wait for events. Ignore interrupts if there's infinite timeout.
        while (true) {
            rc = poll (pollfds, npollfds, timeout);
            if (rc == -1 && errno == EINTR) {
                if (timeout_ < 0)
                    continue;
                else {
                    rc = 0;
                    break;
                }
            }
            errno_assert (rc >= 0);
            break;
        }
        
        //  If timeout was hit with no events signaled, return zero.
        if (rc == 0)
            break;

        //  If timeout was already applied, we don't want to poll anymore.
        //  Setting timeout to zero will cause termination of the function
        //  once the events we've got are processed.
        if (timeout > 0)
            timeout = 0;
    }

    free (pollfds);
    return nevents;

#elif defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS

    fd_set pollset_in;
    FD_ZERO (&pollset_in);
    fd_set pollset_out;
    FD_ZERO (&pollset_out);
    fd_set pollset_err;
    FD_ZERO (&pollset_err);

    zmq::app_thread_t *app_thread = NULL;
    int nsockets = 0;
    zmq::fd_t maxfd = zmq::retired_fd;
    zmq::fd_t notify_fd = zmq::retired_fd;

    //  Ensure we do not attempt to select () on more than FD_SETSIZE
    //  file descriptors.
    zmq_assert (nitems_ <= FD_SETSIZE);

    for (int i = 0; i != nitems_; i++) {

        //  0MQ sockets.
        if (items_ [i].socket) {

            //  Get the app_thread the socket is living in. If there are two
            //  sockets in the same pollset with different app threads, fail.
            zmq::socket_base_t *s = (zmq::socket_base_t*) items_ [i].socket;
            if (app_thread) {
                if (app_thread != s->get_thread ()) {
                    errno = EFAULT;
                    return -1;
                }
            }
            else
                app_thread = s->get_thread ();

            nsockets++;
            continue;
        }

        //  Raw file descriptors.
        if (items_ [i].events & ZMQ_POLLIN)
            FD_SET (items_ [i].fd, &pollset_in);
        if (items_ [i].events & ZMQ_POLLOUT)
            FD_SET (items_ [i].fd, &pollset_out);
        if (items_ [i].events & ZMQ_POLLERR)
            FD_SET (items_ [i].fd, &pollset_err);
        if (maxfd == zmq::retired_fd || maxfd < items_ [i].fd)
            maxfd = items_ [i].fd;
    }

    //  If there's at least one 0MQ socket in the pollset we have to poll
    //  for 0MQ commands. If ZMQ_POLL was not set, fail.
    if (nsockets) {
        notify_fd = app_thread->get_signaler ()->get_fd ();
        if (notify_fd == zmq::retired_fd) {
            errno = ENOTSUP;
            return -1;
        }
        FD_SET (notify_fd, &pollset_in);
        if (maxfd == zmq::retired_fd || maxfd < notify_fd)
            maxfd = notify_fd;
    }

    bool block = (timeout_ < 0);
    timeval timeout = {timeout_ / 1000000, timeout_ % 1000000};
    timeval zero_timeout = {0, 0};
    int nevents = 0;

    //  First iteration just check for events, don't block. Waiting would
    //  prevent exiting on any events that may already been signaled on
    //  0MQ sockets.
    fd_set inset, outset, errset;
    memcpy (&inset, &pollset_in, sizeof (fd_set));
    memcpy (&outset, &pollset_out, sizeof (fd_set));
    memcpy (&errset, &pollset_err, sizeof (fd_set));
    int rc = select (maxfd, &inset, &outset, &errset, &zero_timeout);
#if defined ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    if (rc == -1 && errno == EINTR && timeout_ >= 0)
        return 0;
    errno_assert (rc >= 0 || (rc == -1 && errno == EINTR));
#endif

    while (true) {

        //  Process 0MQ commands if needed.
        if (nsockets && FD_ISSET (notify_fd, &inset))
            if (!app_thread->process_commands (false, false)) {
                errno = ETERM;
                return -1;
            }

        //  Check for the events.
        for (int i = 0; i != nitems_; i++) {

            //  If the poll item is a raw file descriptor, simply convert
            //  the events to zmq_pollitem_t-style format.
            if (!items_ [i].socket) {
                items_ [i].revents = 0;
                if (FD_ISSET (items_ [i].fd, &inset))
                    items_ [i].revents |= ZMQ_POLLIN;
                if (FD_ISSET (items_ [i].fd, &outset))
                    items_ [i].revents |= ZMQ_POLLOUT;
                if (FD_ISSET (items_ [i].fd, &errset))
                    items_ [i].revents |= ZMQ_POLLERR;
                if (items_ [i].revents)
                    nevents++;
                continue;
            }

            //  The poll item is a 0MQ socket.
            zmq::socket_base_t *s = (zmq::socket_base_t*) items_ [i].socket;
            items_ [i].revents = 0;
            if ((items_ [i].events & ZMQ_POLLOUT) && s->has_out ())
                items_ [i].revents |= ZMQ_POLLOUT;
            if ((items_ [i].events & ZMQ_POLLIN) && s->has_in ())
                items_ [i].revents |= ZMQ_POLLIN;
            if (items_ [i].revents)
                nevents++;
        }

        //  If there's at least one event, or if we are asked not to block,
        //  return immediately.
        if (nevents || (timeout.tv_sec == 0 && timeout.tv_usec == 0))
            break;

        //  Wait for events. Ignore interrupts if there's infinite timeout.
        while (true) {
            memcpy (&inset, &pollset_in, sizeof (fd_set));
            memcpy (&outset, &pollset_out, sizeof (fd_set));
            memcpy (&errset, &pollset_err, sizeof (fd_set));
            rc = select (maxfd, &inset, &outset, &errset,
                block ? NULL : &timeout);
#if defined ZMQ_HAVE_WINDOWS
            wsa_assert (rc != SOCKET_ERROR);
#else
            if (rc == -1 && errno == EINTR) {
                if (timeout_ < 0)
                    continue;
                else {
                    rc = 0;
                    break;
                }
            }
            errno_assert (rc >= 0);
#endif
            break;
        }
        
        //  If timeout was hit with no events signaled, return zero.
        if (rc == 0)
            break;

        //  If timeout was already applied, we don't want to poll anymore.
        //  Setting timeout to zero will cause termination of the function
        //  once the events we've got are processed.
        if (!block)
            timeout = zero_timeout;
    }

    return nevents;

#else
    errno = ENOTSUP;
    return -1;
#endif
}

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

