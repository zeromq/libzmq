/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_EPOLL
#include "epoll.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <algorithm>
#include <new>

#include "macros.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

#ifdef ZMQ_HAVE_WINDOWS
const zmq::epoll_t::epoll_fd_t zmq::epoll_t::epoll_retired_fd =
  INVALID_HANDLE_VALUE;
#endif

zmq::epoll_t::epoll_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_), _manual_ready (false)
{
#ifdef ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC
    //  Setting this option result in sane behaviour when exec() functions
    //  are used. Old sockets are closed and don't block TCP ports, avoid
    //  leaks, etc.
    _epoll_fd = epoll_create1 (EPOLL_CLOEXEC);
#else
    _epoll_fd = epoll_create (1);
#endif
    errno_assert (_epoll_fd != epoll_retired_fd);
}

zmq::epoll_t::~epoll_t ()
{
    //  Wait till the worker thread exits.
    stop_worker ();

#ifdef ZMQ_HAVE_WINDOWS
    epoll_close (_epoll_fd);
#else
    close (_epoll_fd);
#endif
    for (retired_t::iterator it = _retired.begin (), end = _retired.end ();
         it != end; ++it) {
        LIBZMQ_DELETE (*it);
    }
}

zmq::epoll_t::handle_t zmq::epoll_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    check_thread ();
    poll_entry_t *pe = new (std::nothrow) poll_entry_t;
    alloc_assert (pe);

    //  The memset is not actually needed. It's here to prevent debugging
    //  tools to complain about using uninitialised memory.
    memset (pe, 0, sizeof (poll_entry_t));

    pe->fd = fd_;
    pe->ev.events = 0;
    pe->ev.data.ptr = pe;
    pe->events = events_;

    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_ADD, fd_, &pe->ev);
    errno_assert (rc != -1);

    //  Increase the load metric of the thread.
    adjust_load (1);

    return pe;
}

void zmq::epoll_t::rm_fd (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = static_cast<poll_entry_t *> (handle_);
    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_DEL, pe->fd, &pe->ev);
    errno_assert (rc != -1);
    pe->fd = retired_fd;
    _retired.push_back (pe);

    //  Decrease the load metric of the thread.
    adjust_load (-1);
}

void zmq::epoll_t::set_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = static_cast<poll_entry_t *> (handle_);
    pe->ev.events |= EPOLLIN;
    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_t::reset_pollin (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = static_cast<poll_entry_t *> (handle_);
    pe->ev.events &= ~(static_cast<uint32_t> (EPOLLIN));
    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_t::set_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = static_cast<poll_entry_t *> (handle_);
    pe->ev.events |= EPOLLOUT;
    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_t::reset_pollout (handle_t handle_)
{
    check_thread ();
    poll_entry_t *pe = static_cast<poll_entry_t *> (handle_);
    pe->ev.events &= ~(static_cast<uint32_t> (EPOLLOUT));
    const int rc = epoll_ctl (_epoll_fd, EPOLL_CTL_MOD, pe->fd, &pe->ev);
    errno_assert (rc != -1);
}

void zmq::epoll_t::stop ()
{
    check_thread ();
}

int zmq::epoll_t::max_fds ()
{
    return -1;
}

void zmq::epoll_t::loop ()
{
    while (run_once (-1)) {
    }
}

bool zmq::epoll_t::run_once (int timeout_ms_)
{
    return run_once_impl<false> (timeout_ms_, NULL);
}

bool zmq::epoll_t::run_once (int timeout_ms_, poller_step_t *step_)
{
    check_thread ();
    return run_once_impl<true> (timeout_ms_, step_);
}

template <bool Manual>
bool zmq::epoll_t::run_once_impl (int timeout_ms_, poller_step_t *step_)
{
    epoll_event ev_buf[max_io_events];

    //  Execute any due timers.
    const int timeout =
      static_cast<int> (Manual ? execute_timers (step_) : execute_timers ());
    const int wait =
      Manual && (step_->progress () || step_->more || step_->probe) ? 0
      : timeout_ms_ < 0 ? (timeout ? timeout : -1)
      : timeout         ? std::min (timeout, timeout_ms_)
                        : timeout_ms_;

    if (get_load () == 0) {
        if (timeout == 0)
            return false;

        // TODO sleep for timeout
        return true;
    }

    //  Wait for events.
    int n;
    if (Manual && _manual_ready) {
        ev_buf[0] = _manual_event;
        _manual_ready = false;
        n = 1;
    } else
        n = epoll_wait (
          _epoll_fd, &ev_buf[0],
          Manual ? step_->event_batch (max_io_events) : max_io_events, wait);
    if (n == -1) {
        errno_assert (errno == EINTR);
        if (Manual)
            step_->error = EINTR;
        return true;
    }

    for (int i = 0; i < n; i++) {
        const poll_entry_t *const pe =
          static_cast<const poll_entry_t *> (ev_buf[i].data.ptr);

        if (NULL == pe)
            continue;
        if (NULL == pe->events)
            continue;
        if (pe->fd == retired_fd)
            continue;
        if (Manual && !step_->event ()) {
            //  A readiness probe advances the native queue too. Retain its
            //  record until dispatched, while the usual retirement rules hold.
            _manual_event = ev_buf[i];
            _manual_ready = true;
            break;
        }
        if (ev_buf[i].events & (EPOLLERR | EPOLLHUP))
            pe->events->in_event ();
        if (pe->fd == retired_fd)
            continue;
        if (ev_buf[i].events & EPOLLOUT)
            pe->events->out_event ();
        if (pe->fd == retired_fd)
            continue;
        if (ev_buf[i].events & EPOLLIN)
            pe->events->in_event ();
    }

    //  Destroy retired event sources.
    for (retired_t::iterator it = _retired.begin (), end = _retired.end ();
         it != end; ++it) {
        LIBZMQ_DELETE (*it);
    }
    _retired.clear ();
    return true;
}

#endif
