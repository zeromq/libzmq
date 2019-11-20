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
#include "select.hpp"
#if defined ZMQ_IOTHREAD_POLLER_USE_SELECT

#if defined ZMQ_HAVE_WINDOWS
#elif defined ZMQ_HAVE_HPUX
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#elif defined ZMQ_HAVE_OPENVMS
#include <sys/types.h>
#include <sys/time.h>
#elif defined ZMQ_HAVE_VXWORKS
#include <sys/types.h>
#include <sys/time.h>
#include <strings.h>
#else
#include <sys/select.h>
#endif

#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

#include <algorithm>
#include <limits>
#include <climits>

zmq::select_t::select_t (const zmq::thread_ctx_t &ctx_) :
    worker_poller_base_t (ctx_),
#if defined ZMQ_HAVE_WINDOWS
    //  Fine as long as map is not cleared.
    _current_family_entry_it (_family_entries.end ())
#else
    _max_fd (retired_fd)
#endif
{
#if defined ZMQ_HAVE_WINDOWS
    for (size_t i = 0; i < fd_family_cache_size; ++i)
        _fd_family_cache[i] = std::make_pair (retired_fd, 0);
#endif
}

zmq::select_t::~select_t ()
{
    stop_worker ();
}

zmq::select_t::handle_t zmq::select_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    check_thread ();
    zmq_assert (fd_ != retired_fd);

    fd_entry_t fd_entry;
    fd_entry.fd = fd_;
    fd_entry.events = events_;

#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (fd_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t &family_entry = _family_entries[family];
#else
    family_entry_t &family_entry = _family_entry;
#endif
    family_entry.fd_entries.push_back (fd_entry);
    FD_SET (fd_, &family_entry.fds_set.error);

#if !defined ZMQ_HAVE_WINDOWS
    if (fd_ > _max_fd)
        _max_fd = fd_;
#endif

    adjust_load (1);

    return fd_;
}

zmq::select_t::fd_entries_t::iterator
zmq::select_t::find_fd_entry_by_handle (fd_entries_t &fd_entries_,
                                        handle_t handle_)
{
    fd_entries_t::iterator fd_entry_it;
    for (fd_entry_it = fd_entries_.begin (); fd_entry_it != fd_entries_.end ();
         ++fd_entry_it)
        if (fd_entry_it->fd == handle_)
            break;

    return fd_entry_it;
}

void zmq::select_t::trigger_events (const fd_entries_t &fd_entries_,
                                    const fds_set_t &local_fds_set_,
                                    int event_count_)
{
    //  Size is cached to avoid iteration through recently added descriptors.
    for (fd_entries_t::size_type i = 0, size = fd_entries_.size ();
         i < size && event_count_ > 0; ++i) {
        //  fd_entries_[i] may not be stored, since calls to
        //  in_event/out_event may reallocate the vector

        if (is_retired_fd (fd_entries_[i]))
            continue;

        if (FD_ISSET (fd_entries_[i].fd, &local_fds_set_.read)) {
            fd_entries_[i].events->in_event ();
            --event_count_;
        }

        //  TODO: can the is_retired_fd be true at this point? if it
        //  was retired before, we would already have continued, and I
        //  don't see where it might have been modified
        //  And if rc == 0, we can break instead of continuing
        if (is_retired_fd (fd_entries_[i]) || event_count_ == 0)
            continue;

        if (FD_ISSET (fd_entries_[i].fd, &local_fds_set_.write)) {
            fd_entries_[i].events->out_event ();
            --event_count_;
        }

        //  TODO: same as above
        if (is_retired_fd (fd_entries_[i]) || event_count_ == 0)
            continue;

        if (FD_ISSET (fd_entries_[i].fd, &local_fds_set_.error)) {
            fd_entries_[i].events->in_event ();
            --event_count_;
        }
    }
}

#if defined ZMQ_HAVE_WINDOWS
int zmq::select_t::try_retire_fd_entry (
  family_entries_t::iterator family_entry_it_, zmq::fd_t &handle_)
{
    family_entry_t &family_entry = family_entry_it_->second;

    fd_entries_t::iterator fd_entry_it =
      find_fd_entry_by_handle (family_entry.fd_entries, handle_);

    if (fd_entry_it == family_entry.fd_entries.end ())
        return 0;

    fd_entry_t &fd_entry = *fd_entry_it;
    zmq_assert (fd_entry.fd != retired_fd);

    if (family_entry_it_ != _current_family_entry_it) {
        //  Family is not currently being iterated and can be safely
        //  modified in-place. So later it can be skipped without
        //  re-verifying its content.
        family_entry.fd_entries.erase (fd_entry_it);
    } else {
        //  Otherwise mark removed entries as retired. It will be cleaned up
        //  at the end of the iteration. See zmq::select_t::loop
        fd_entry.fd = retired_fd;
        family_entry.has_retired = true;
    }
    family_entry.fds_set.remove_fd (handle_);
    return 1;
}
#endif

void zmq::select_t::rm_fd (handle_t handle_)
{
    check_thread ();
    int retired = 0;
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    if (family != AF_UNSPEC) {
        family_entries_t::iterator family_entry_it =
          _family_entries.find (family);

        retired += try_retire_fd_entry (family_entry_it, handle_);
    } else {
        //  get_fd_family may fail and return AF_UNSPEC if the socket was not
        //  successfully connected. In that case, we need to look for the
        //  socket in all family_entries.
        family_entries_t::iterator end = _family_entries.end ();
        for (family_entries_t::iterator family_entry_it =
               _family_entries.begin ();
             family_entry_it != end; ++family_entry_it) {
            if (retired += try_retire_fd_entry (family_entry_it, handle_)) {
                break;
            }
        }
    }
#else
    fd_entries_t::iterator fd_entry_it =
      find_fd_entry_by_handle (_family_entry.fd_entries, handle_);
    assert (fd_entry_it != _family_entry.fd_entries.end ());

    zmq_assert (fd_entry_it->fd != retired_fd);
    fd_entry_it->fd = retired_fd;
    _family_entry.fds_set.remove_fd (handle_);

    ++retired;

    if (handle_ == _max_fd) {
        _max_fd = retired_fd;
        for (fd_entry_it = _family_entry.fd_entries.begin ();
             fd_entry_it != _family_entry.fd_entries.end (); ++fd_entry_it)
            if (fd_entry_it->fd > _max_fd)
                _max_fd = fd_entry_it->fd;
    }

    _family_entry.has_retired = true;
#endif
    zmq_assert (retired == 1);
    adjust_load (-1);
}

void zmq::select_t::set_pollin (handle_t handle_)
{
    check_thread ();
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t &family_entry = _family_entries[family];
#else
    family_entry_t &family_entry = _family_entry;
#endif
    FD_SET (handle_, &family_entry.fds_set.read);
}

void zmq::select_t::reset_pollin (handle_t handle_)
{
    check_thread ();
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t &family_entry = _family_entries[family];
#else
    family_entry_t &family_entry = _family_entry;
#endif
    FD_CLR (handle_, &family_entry.fds_set.read);
}

void zmq::select_t::set_pollout (handle_t handle_)
{
    check_thread ();
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t &family_entry = _family_entries[family];
#else
    family_entry_t &family_entry = _family_entry;
#endif
    FD_SET (handle_, &family_entry.fds_set.write);
}

void zmq::select_t::reset_pollout (handle_t handle_)
{
    check_thread ();
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t &family_entry = _family_entries[family];
#else
    family_entry_t &family_entry = _family_entry;
#endif
    FD_CLR (handle_, &family_entry.fds_set.write);
}

void zmq::select_t::stop ()
{
    check_thread ();
    //  no-op... thread is stopped when no more fds or timers are registered
}

int zmq::select_t::max_fds ()
{
    return FD_SETSIZE;
}

void zmq::select_t::loop ()
{
    while (true) {
        //  Execute any due timers.
        int timeout = static_cast<int> (execute_timers ());

        cleanup_retired ();

#ifdef _WIN32
        if (_family_entries.empty ()) {
#else
        if (_family_entry.fd_entries.empty ()) {
#endif
            zmq_assert (get_load () == 0);

            if (timeout == 0)
                break;

            // TODO sleep for timeout
            continue;
        }

#if defined ZMQ_HAVE_OSX
        struct timeval tv = {(long) (timeout / 1000), timeout % 1000 * 1000};
#else
        struct timeval tv = {static_cast<long> (timeout / 1000),
                             static_cast<long> (timeout % 1000 * 1000)};
#endif

#if defined ZMQ_HAVE_WINDOWS
        /*
            On Windows select does not allow to mix descriptors from different
            service providers. It seems to work for AF_INET and AF_INET6,
            but fails for AF_INET and VMCI. The workaround is to use
            WSAEventSelect and WSAWaitForMultipleEvents to wait, then use
            select to find out what actually changed. WSAWaitForMultipleEvents
            cannot be used alone, because it does not support more than 64 events
            which is not enough.

            To reduce unnecessary overhead, WSA is only used when there are more
            than one family. Moreover, AF_INET and AF_INET6 are considered the same
            family because Windows seems to handle them properly.
            See get_fd_family for details.
        */

        //  If there is just one family, there is no reason to use WSA events.
        int rc = 0;
        const bool use_wsa_events = _family_entries.size () > 1;
        if (use_wsa_events) {
            // TODO: I don't really understand why we are doing this. If any of
            // the events was signaled, we will call select for each fd_family
            // afterwards. The only benefit is if none of the events was
            // signaled, then we continue early.
            // IMHO, either WSAEventSelect/WSAWaitForMultipleEvents or select
            // should be used, but not both

            wsa_events_t wsa_events;

            for (family_entries_t::iterator family_entry_it =
                   _family_entries.begin ();
                 family_entry_it != _family_entries.end (); ++family_entry_it) {
                family_entry_t &family_entry = family_entry_it->second;

                for (fd_entries_t::iterator fd_entry_it =
                       family_entry.fd_entries.begin ();
                     fd_entry_it != family_entry.fd_entries.end ();
                     ++fd_entry_it) {
                    fd_t fd = fd_entry_it->fd;

                    //  http://stackoverflow.com/q/35043420/188530
                    if (FD_ISSET (fd, &family_entry.fds_set.read)
                        && FD_ISSET (fd, &family_entry.fds_set.write))
                        rc = WSAEventSelect (fd, wsa_events.events[3],
                                             FD_READ | FD_ACCEPT | FD_CLOSE
                                               | FD_WRITE | FD_CONNECT);
                    else if (FD_ISSET (fd, &family_entry.fds_set.read))
                        rc = WSAEventSelect (fd, wsa_events.events[0],
                                             FD_READ | FD_ACCEPT | FD_CLOSE);
                    else if (FD_ISSET (fd, &family_entry.fds_set.write))
                        rc = WSAEventSelect (fd, wsa_events.events[1],
                                             FD_WRITE | FD_CONNECT);
                    else
                        rc = 0;

                    wsa_assert (rc != SOCKET_ERROR);
                }
            }

            rc = WSAWaitForMultipleEvents (4, wsa_events.events, FALSE,
                                           timeout ? timeout : INFINITE, FALSE);
            wsa_assert (rc != (int) WSA_WAIT_FAILED);
            zmq_assert (rc != WSA_WAIT_IO_COMPLETION);

            if (rc == WSA_WAIT_TIMEOUT)
                continue;
        }

        for (_current_family_entry_it = _family_entries.begin ();
             _current_family_entry_it != _family_entries.end ();
             ++_current_family_entry_it) {
            family_entry_t &family_entry = _current_family_entry_it->second;


            if (use_wsa_events) {
                //  There is no reason to wait again after WSAWaitForMultipleEvents.
                //  Simply collect what is ready.
                struct timeval tv_nodelay = {0, 0};
                select_family_entry (family_entry, 0, true, tv_nodelay);
            } else {
                select_family_entry (family_entry, 0, timeout > 0, tv);
            }
        }
#else
        select_family_entry (_family_entry, _max_fd + 1, timeout > 0, tv);
#endif
    }
}

void zmq::select_t::select_family_entry (family_entry_t &family_entry_,
                                         const int max_fd_,
                                         const bool use_timeout_,
                                         struct timeval &tv_)
{
    //  select will fail when run with empty sets.
    fd_entries_t &fd_entries = family_entry_.fd_entries;
    if (fd_entries.empty ())
        return;

    fds_set_t local_fds_set = family_entry_.fds_set;
    int rc = select (max_fd_, &local_fds_set.read, &local_fds_set.write,
                     &local_fds_set.error, use_timeout_ ? &tv_ : NULL);

#if defined ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    if (rc == -1) {
        errno_assert (errno == EINTR);
        return;
    }
#endif

    trigger_events (fd_entries, local_fds_set, rc);

    cleanup_retired (family_entry_);
}

zmq::select_t::fds_set_t::fds_set_t ()
{
    FD_ZERO (&read);
    FD_ZERO (&write);
    FD_ZERO (&error);
}

zmq::select_t::fds_set_t::fds_set_t (const fds_set_t &other_)
{
#if defined ZMQ_HAVE_WINDOWS
    // On Windows we don't need to copy the whole fd_set.
    // SOCKETS are continuous from the beginning of fd_array in fd_set.
    // We just need to copy fd_count elements of fd_array.
    // We gain huge memcpy() improvement if number of used SOCKETs is much lower than FD_SETSIZE.
    memcpy (&read, &other_.read,
            (char *) (other_.read.fd_array + other_.read.fd_count)
              - (char *) &other_.read);
    memcpy (&write, &other_.write,
            (char *) (other_.write.fd_array + other_.write.fd_count)
              - (char *) &other_.write);
    memcpy (&error, &other_.error,
            (char *) (other_.error.fd_array + other_.error.fd_count)
              - (char *) &other_.error);
#else
    memcpy (&read, &other_.read, sizeof other_.read);
    memcpy (&write, &other_.write, sizeof other_.write);
    memcpy (&error, &other_.error, sizeof other_.error);
#endif
}

zmq::select_t::fds_set_t &zmq::select_t::fds_set_t::
operator= (const fds_set_t &other_)
{
#if defined ZMQ_HAVE_WINDOWS
    // On Windows we don't need to copy the whole fd_set.
    // SOCKETS are continuous from the beginning of fd_array in fd_set.
    // We just need to copy fd_count elements of fd_array.
    // We gain huge memcpy() improvement if number of used SOCKETs is much lower than FD_SETSIZE.
    memcpy (&read, &other_.read,
            (char *) (other_.read.fd_array + other_.read.fd_count)
              - (char *) &other_.read);
    memcpy (&write, &other_.write,
            (char *) (other_.write.fd_array + other_.write.fd_count)
              - (char *) &other_.write);
    memcpy (&error, &other_.error,
            (char *) (other_.error.fd_array + other_.error.fd_count)
              - (char *) &other_.error);
#else
    memcpy (&read, &other_.read, sizeof other_.read);
    memcpy (&write, &other_.write, sizeof other_.write);
    memcpy (&error, &other_.error, sizeof other_.error);
#endif
    return *this;
}

void zmq::select_t::fds_set_t::remove_fd (const fd_t &fd_)
{
    FD_CLR (fd_, &read);
    FD_CLR (fd_, &write);
    FD_CLR (fd_, &error);
}

bool zmq::select_t::cleanup_retired (family_entry_t &family_entry_)
{
    if (family_entry_.has_retired) {
        family_entry_.has_retired = false;
        family_entry_.fd_entries.erase (
          std::remove_if (family_entry_.fd_entries.begin (),
                          family_entry_.fd_entries.end (), is_retired_fd),
          family_entry_.fd_entries.end ());
    }
    return family_entry_.fd_entries.empty ();
}

void zmq::select_t::cleanup_retired ()
{
#ifdef _WIN32
    for (family_entries_t::iterator it = _family_entries.begin ();
         it != _family_entries.end ();) {
        if (cleanup_retired (it->second))
            it = _family_entries.erase (it);
        else
            ++it;
    }
#else
    cleanup_retired (_family_entry);
#endif
}

bool zmq::select_t::is_retired_fd (const fd_entry_t &entry_)
{
    return entry_.fd == retired_fd;
}

zmq::select_t::family_entry_t::family_entry_t () : has_retired (false)
{
}


#if defined ZMQ_HAVE_WINDOWS
u_short zmq::select_t::get_fd_family (fd_t fd_)
{
    // cache the results of determine_fd_family, as this is frequently called
    // for the same sockets, and determine_fd_family is expensive
    size_t i;
    for (i = 0; i < fd_family_cache_size; ++i) {
        const std::pair<fd_t, u_short> &entry = _fd_family_cache[i];
        if (entry.first == fd_) {
            return entry.second;
        }
        if (entry.first == retired_fd)
            break;
    }

    std::pair<fd_t, u_short> res =
      std::make_pair (fd_, determine_fd_family (fd_));
    if (i < fd_family_cache_size) {
        _fd_family_cache[i] = res;
    } else {
        // just overwrite a random entry
        // could be optimized by some LRU strategy
        _fd_family_cache[rand () % fd_family_cache_size] = res;
    }

    return res.second;
}

u_short zmq::select_t::determine_fd_family (fd_t fd_)
{
    //  Use sockaddr_storage instead of sockaddr to accommodate different structure sizes
    sockaddr_storage addr = {0};
    int addr_size = sizeof addr;

    int type;
    int type_length = sizeof (int);

    int rc = getsockopt (fd_, SOL_SOCKET, SO_TYPE,
                         reinterpret_cast<char *> (&type), &type_length);

    if (rc == 0) {
        if (type == SOCK_DGRAM)
            return AF_INET;

        rc =
          getsockname (fd_, reinterpret_cast<sockaddr *> (&addr), &addr_size);

        //  AF_INET and AF_INET6 can be mixed in select
        //  TODO: If proven otherwise, should simply return addr.sa_family
        if (rc != SOCKET_ERROR)
            return addr.ss_family == AF_INET6 ? AF_INET : addr.ss_family;
    }

    return AF_UNSPEC;
}

zmq::select_t::wsa_events_t::wsa_events_t ()
{
    events[0] = WSACreateEvent ();
    wsa_assert (events[0] != WSA_INVALID_EVENT);
    events[1] = WSACreateEvent ();
    wsa_assert (events[1] != WSA_INVALID_EVENT);
    events[2] = WSACreateEvent ();
    wsa_assert (events[2] != WSA_INVALID_EVENT);
    events[3] = WSACreateEvent ();
    wsa_assert (events[3] != WSA_INVALID_EVENT);
}

zmq::select_t::wsa_events_t::~wsa_events_t ()
{
    wsa_assert (WSACloseEvent (events[0]));
    wsa_assert (WSACloseEvent (events[1]));
    wsa_assert (WSACloseEvent (events[2]));
    wsa_assert (WSACloseEvent (events[3]));
}
#endif

#endif
