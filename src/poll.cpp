/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "poll.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_POLL

#include <sys/types.h>
#include <sys/time.h>
#include <poll.h>
#include <algorithm>

#include "poll.hpp"
#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

zmq::poll_t::poll_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_), retired (false)
{
}

zmq::poll_t::~poll_t ()
{
    stop_worker ();
}

zmq::poll_t::handle_t zmq::poll_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    check_thread ();
    zmq_assert (fd_ != retired_fd);

    //  If the file descriptor table is too small expand it.
    fd_table_t::size_type sz = fd_table.size ();
    if (sz <= (fd_table_t::size_type) fd_) {
        fd_table.resize (fd_ + 1);
        while (sz != (fd_table_t::size_type) (fd_ + 1)) {
            fd_table[sz].index = retired_fd;
            ++sz;
        }
    }

    pollfd pfd = {fd_, 0, 0};
    pollset.push_back (pfd);
    zmq_assert (fd_table[fd_].index == retired_fd);

    fd_table[fd_].index = pollset.size () - 1;
    fd_table[fd_].events = events_;

    //  Increase the load metric of the thread.
    adjust_load (1);

    return fd_;
}

void zmq::poll_t::rm_fd (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    zmq_assert (index != retired_fd);

    //  Mark the fd as unused.
    pollset[index].fd = retired_fd;
    fd_table[handle_].index = retired_fd;
    retired = true;

    //  Decrease the load metric of the thread.
    adjust_load (-1);
}

void zmq::poll_t::set_pollin (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events |= POLLIN;
}

void zmq::poll_t::reset_pollin (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events &= ~((short) POLLIN);
}

void zmq::poll_t::set_pollout (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events |= POLLOUT;
}

void zmq::poll_t::reset_pollout (handle_t handle_)
{
    check_thread ();
    fd_t index = fd_table[handle_].index;
    pollset[index].events &= ~((short) POLLOUT);
}

void zmq::poll_t::stop ()
{
    check_thread ();
    //  no-op... thread is stopped when no more fds or timers are registered
}

int zmq::poll_t::max_fds ()
{
    return -1;
}

void zmq::poll_t::loop ()
{
    while (run_once (-1)) {
    }
}

bool zmq::poll_t::run_once (int timeout_ms_)
{
    //  Execute any due timers.
    int timeout = (int) execute_timers ();
    const int wait =
      timeout_ms_ < 0 ? (timeout ? timeout : -1)
                     : timeout ? std::min (timeout, timeout_ms_) : timeout_ms_;

    cleanup_retired ();

    if (pollset.empty ()) {
        zmq_assert (get_load () == 0);

        if (timeout == 0)
            return false;

        // TODO sleep for timeout
        return true;
    }

    //  Wait for events.
    int rc = poll (&pollset[0], static_cast<nfds_t> (pollset.size ()),
                   wait);
    if (rc == -1) {
        errno_assert (errno == EINTR);
        return true;
    }

    //  If there are no events (i.e. it's a timeout) there's no point
    //  in checking the pollset.
    if (rc == 0)
        return true;

    for (pollset_t::size_type i = 0; i != pollset.size (); i++) {
        zmq_assert (!(pollset[i].revents & POLLNVAL));
        if (pollset[i].fd == retired_fd)
            continue;
        if (pollset[i].revents & (POLLERR | POLLHUP))
            fd_table[pollset[i].fd].events->in_event ();
        if (pollset[i].fd == retired_fd)
            continue;
        if (pollset[i].revents & POLLOUT)
            fd_table[pollset[i].fd].events->out_event ();
        if (pollset[i].fd == retired_fd)
            continue;
        if (pollset[i].revents & POLLIN)
            fd_table[pollset[i].fd].events->in_event ();
    }
    return true;
}

void zmq::poll_t::cleanup_retired ()
{
    //  Clean up the pollset and update the fd_table accordingly.
    if (retired) {
        pollset_t::size_type i = 0;
        while (i < pollset.size ()) {
            if (pollset[i].fd == retired_fd)
                pollset.erase (pollset.begin () + i);
            else {
                fd_table[pollset[i].fd].index = i;
                i++;
            }
        }
        retired = false;
    }
}


#endif
