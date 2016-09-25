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
#if defined ZMQ_USE_SELECT

#if defined ZMQ_HAVE_WINDOWS
#elif defined ZMQ_HAVE_HPUX
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#elif defined ZMQ_HAVE_OPENVMS
#include <sys/types.h>
#include <sys/time.h>
#else
#include <sys/select.h>
#endif

#include "err.hpp"
#include "config.hpp"
#include "i_poll_events.hpp"

zmq::select_t::select_t (const zmq::ctx_t &ctx_) :
    ctx (ctx_),
#if defined ZMQ_HAVE_WINDOWS
    //  Fine as long as map is not cleared.
    current_family_entry_it (family_entries.end ()),
#else
    retired (false),
    maxfd (retired_fd),
#endif
    stopping (false)
{
}

zmq::select_t::~select_t ()
{
    worker.stop ();
}

zmq::select_t::handle_t zmq::select_t::add_fd (fd_t fd_, i_poll_events *events_)
{
    fd_entry_t fd_entry;
    fd_entry.fd = fd_;
    fd_entry.events = events_;

#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (fd_);
    wsa_assert (family != AF_UNSPEC);
    family_entry_t& family_entry = family_entries [family];
    family_entry.fd_entries.push_back (fd_entry);
    FD_SET (fd_, &family_entry.fds_set.error);
#else
    fd_entries.push_back (fd_entry);
    FD_SET (fd_, &fds_set.error);

    if (fd_ > maxfd)
        maxfd = fd_;
#endif

    adjust_load (1);

    return fd_;
}

void zmq::select_t::rm_fd (handle_t handle_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);

    family_entries_t::iterator family_entry_it = family_entries.find (family);
    family_entry_t& family_entry = family_entry_it->second;

    if (family_entry_it != current_family_entry_it) {
        //  Family is not currently being iterated and can be safely
        //  modified in-place. So later it can be skipped without
        //  re-verifying its content.
        fd_entries_t::iterator fd_entry_it;
        for (fd_entry_it = family_entry.fd_entries.begin ();
              fd_entry_it != family_entry.fd_entries.end (); ++fd_entry_it)
            if (fd_entry_it->fd == handle_)
                break;
        zmq_assert (fd_entry_it != family_entry.fd_entries.end ());

        family_entry.fd_entries.erase (fd_entry_it);
        family_entry.fds_set.remove_fd (handle_);
    } else {
        //  Otherwise mark removed entries as retired. It will be cleaned up
        //  at the end of the iteration. See zmq::select_t::loop
        fd_entries_t::iterator fd_entry_it;
        for (fd_entry_it = family_entry.fd_entries.begin ();
              fd_entry_it != family_entry.fd_entries.end (); ++fd_entry_it)
            if (fd_entry_it->fd == handle_)
                break;
        zmq_assert (fd_entry_it != family_entry.fd_entries.end ());

        fd_entry_it->fd = retired_fd;
        family_entry.fds_set.remove_fd (handle_);
        family_entry.retired = true;
    }
#else
    fd_entries_t::iterator fd_entry_it;
    for (fd_entry_it = fd_entries.begin ();
          fd_entry_it != fd_entries.end (); ++fd_entry_it)
        if (fd_entry_it->fd == handle_)
            break;
    zmq_assert (fd_entry_it != fd_entries.end ());

    fd_entry_it->fd = retired_fd;
    fds_set.remove_fd (handle_);

    if (handle_ == maxfd) {
        maxfd = retired_fd;
        for (fd_entry_it = fd_entries.begin (); fd_entry_it != fd_entries.end ();
              ++fd_entry_it)
            if (fd_entry_it->fd > maxfd)
                maxfd = fd_entry_it->fd;
    }

    retired = true;
#endif
    adjust_load (-1);
}

void zmq::select_t::set_pollin (handle_t handle_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    FD_SET (handle_, &family_entries [family].fds_set.read);
#else
    FD_SET (handle_, &fds_set.read);
#endif
}

void zmq::select_t::reset_pollin (handle_t handle_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    FD_CLR (handle_, &family_entries [family].fds_set.read);
#else
    FD_CLR (handle_, &fds_set.read);
#endif
}

void zmq::select_t::set_pollout (handle_t handle_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    FD_SET (handle_, &family_entries [family].fds_set.write);
#else
    FD_SET (handle_, &fds_set.write);
#endif
}

void zmq::select_t::reset_pollout (handle_t handle_)
{
#if defined ZMQ_HAVE_WINDOWS
    u_short family = get_fd_family (handle_);
    wsa_assert (family != AF_UNSPEC);
    FD_CLR (handle_, &family_entries [family].fds_set.write);
#else
    FD_CLR (handle_, &fds_set.write);
#endif
}

void zmq::select_t::start ()
{
    ctx.start_thread (worker, worker_routine, this);
}

void zmq::select_t::stop ()
{
    stopping = true;
}

int zmq::select_t::max_fds ()
{
    return FD_SETSIZE;
}

void zmq::select_t::loop ()
{
    while (!stopping) {
        //  Execute any due timers.
        int timeout = (int) execute_timers ();

#if defined ZMQ_HAVE_OSX
        struct timeval tv = { (long) (timeout / 1000), timeout % 1000 * 1000 };
#else
        struct timeval tv = { (long) (timeout / 1000), (long) (timeout % 1000 * 1000) };
#endif

        int rc = 0;

#if defined ZMQ_HAVE_WINDOWS
        /*
            On Windows select does not allow to mix descriptors from different
            service providers. It seems to work for AF_INET and AF_INET6,
            but fails for AF_INET and VMCI. The workaround is to use
            WSAEventSelect and WSAWaitForMultipleEvents to wait, then use
            select to find out what actually changed. WSAWaitForMultipleEvents
            cannot be used alone, because it does not support more than 64 events
            which is not enough.

            To reduce unncessary overhead, WSA is only used when there are more
            than one family. Moreover, AF_INET and AF_INET6 are considered the same
            family because Windows seems to handle them properly.
            See get_fd_family for details.
        */
        wsa_events_t wsa_events;

        //  If there is just one family, there is no reason to use WSA events.
        if (family_entries.size () > 1) {
            for (family_entries_t::iterator family_entry_it = family_entries.begin ();
                  family_entry_it != family_entries.end (); ++family_entry_it) {
                family_entry_t& family_entry = family_entry_it->second;

                for (fd_entries_t::iterator fd_entry_it = family_entry.fd_entries.begin ();
                      fd_entry_it != family_entry.fd_entries.end (); ++fd_entry_it) {
                    fd_t fd = fd_entry_it->fd;

                    //  http://stackoverflow.com/q/35043420/188530
                    if (FD_ISSET (fd, &family_entry.fds_set.read) &&
                          FD_ISSET (fd, &family_entry.fds_set.write))
                        rc = WSAEventSelect (fd, wsa_events.events [3],
                            FD_READ | FD_ACCEPT | FD_CLOSE | FD_WRITE | FD_CONNECT | FD_OOB);
                    else if (FD_ISSET (fd, &family_entry.fds_set.read))
                        rc = WSAEventSelect (fd, wsa_events.events [0],
                            FD_READ | FD_ACCEPT | FD_CLOSE | FD_OOB);
                    else if (FD_ISSET (fd, &family_entry.fds_set.write))
                        rc = WSAEventSelect (fd, wsa_events.events [1],
                            FD_WRITE | FD_CONNECT | FD_OOB);
                    else if (FD_ISSET (fd, &family_entry.fds_set.error))
                        rc = WSAEventSelect (fd, wsa_events.events [2],
                            FD_OOB);
                    else
                        rc = 0;

                    wsa_assert (rc != SOCKET_ERROR);
                }
            }
        }
#endif

#if defined ZMQ_HAVE_WINDOWS
        if (family_entries.size () > 1) {
            rc = WSAWaitForMultipleEvents (4, wsa_events.events, FALSE,
                timeout ? timeout : INFINITE, FALSE);
            wsa_assert (rc != (int)WSA_WAIT_FAILED);
            zmq_assert (rc != WSA_WAIT_IO_COMPLETION);

            if (rc == WSA_WAIT_TIMEOUT)
                continue;
        }

        for (current_family_entry_it = family_entries.begin ();
              current_family_entry_it != family_entries.end (); ++current_family_entry_it) {
            family_entry_t& family_entry = current_family_entry_it->second;

            //  select will fail when run with empty sets.
            if (family_entry.fd_entries.empty ())
                continue;

            fds_set_t local_fds_set = family_entry.fds_set;

            if (family_entries.size () > 1) {
                //  There is no reason to wait again after WSAWaitForMultipleEvents.
                //  Simply collect what is ready.
                struct timeval tv_nodelay = { 0, 0 };
                rc = select (0, &local_fds_set.read, &local_fds_set.write, &local_fds_set.error,
                    &tv_nodelay);
            }
            else
                rc = select (0, &local_fds_set.read, &local_fds_set.write,
                    &local_fds_set.error, timeout > 0 ? &tv : NULL);

            wsa_assert (rc != SOCKET_ERROR);

            //  Size is cached to avoid iteration through recently added descriptors.
            for (fd_entries_t::size_type i = 0, size = family_entry.fd_entries.size (); i < size && rc > 0; ++i) {

                if (family_entry.fd_entries[i].fd == retired_fd)
                    continue;

                if (FD_ISSET(family_entry.fd_entries[i].fd, &local_fds_set.read)) {
                    family_entry.fd_entries[i].events->in_event();
                    --rc;
                }

                if (family_entry.fd_entries[i].fd == retired_fd || rc == 0)
                    continue;

                if (FD_ISSET(family_entry.fd_entries[i].fd, &local_fds_set.write)) {
                    family_entry.fd_entries[i].events->out_event();
                    --rc;
                }

                if (family_entry.fd_entries[i].fd == retired_fd || rc == 0)
                    continue;

                if (FD_ISSET(family_entry.fd_entries[i].fd, &local_fds_set.error)) {
                    family_entry.fd_entries[i].events->in_event();
                    --rc;
                }
            }

            if (family_entry.retired) {
                family_entry.retired = false;
                family_entry.fd_entries.erase (std::remove_if (family_entry.fd_entries.begin (),
                    family_entry.fd_entries.end (), is_retired_fd), family_entry.fd_entries.end ());
            }
        }
#else
        fds_set_t local_fds_set = fds_set;
        rc = select (maxfd + 1, &local_fds_set.read, &local_fds_set.write,
            &local_fds_set.error, timeout ? &tv : NULL);

        if (rc == -1) {
            errno_assert (errno == EINTR);
            continue;
        }

        //  Size is cached to avoid iteration through just added descriptors.
        for (fd_entries_t::size_type i = 0, size = fd_entries.size (); i < size && rc > 0; ++i) {
            if (fd_entries [i].fd == retired_fd)
                continue;

            if (FD_ISSET (fd_entries [i].fd, &local_fds_set.read)) {
                fd_entries [i].events->in_event ();
                --rc;
            }

            if (fd_entries [i].fd == retired_fd || rc == 0)
                continue;

            if (FD_ISSET (fd_entries [i].fd, &local_fds_set.write)) {
                fd_entries [i].events->out_event ();
                --rc;
            }

            if (fd_entries [i].fd == retired_fd || rc == 0)
                continue;

            if (FD_ISSET (fd_entries [i].fd, &local_fds_set.error)) {
                fd_entries [i].events->in_event ();
                --rc;
            }
        }

        if (retired) {
            retired = false;
            fd_entries.erase (std::remove_if (fd_entries.begin (), fd_entries.end (),
                is_retired_fd), fd_entries.end ());
        }
#endif
    }
}

void zmq::select_t::worker_routine (void *arg_)
{
    ((select_t*) arg_)->loop ();
}

zmq::select_t::fds_set_t::fds_set_t ()
{
    FD_ZERO (&read);
    FD_ZERO (&write);
    FD_ZERO (&error);
}

zmq::select_t::fds_set_t::fds_set_t (const fds_set_t& other_)
{
    memcpy (&read, &other_.read, sizeof other_.read);
    memcpy (&write, &other_.write, sizeof other_.write);
    memcpy (&error, &other_.error, sizeof other_.error);
}

zmq::select_t::fds_set_t& zmq::select_t::fds_set_t::operator= (const fds_set_t& other_)
{
    memcpy (&read, &other_.read, sizeof other_.read);
    memcpy (&write, &other_.write, sizeof other_.write);
    memcpy (&error, &other_.error, sizeof other_.error);
    return *this;
}

void zmq::select_t::fds_set_t::remove_fd (const fd_t& fd_)
{
    FD_CLR (fd_, &read);
    FD_CLR (fd_, &write);
    FD_CLR (fd_, &error);
}

bool zmq::select_t::is_retired_fd (const fd_entry_t &entry)
{
    return (entry.fd == retired_fd);
}

#if defined ZMQ_HAVE_WINDOWS
u_short zmq::select_t::get_fd_family (fd_t fd_)
{
    //  Use sockaddr_storage instead of sockaddr to accomodate differect structure sizes
    sockaddr_storage addr = { 0 };
    int addr_size = sizeof addr;

    int type;
    int type_length = sizeof(int);

    int rc = getsockopt(fd_, SOL_SOCKET, SO_TYPE, (char*) &type, &type_length);

    if (rc == 0) {
        if (type == SOCK_DGRAM)
            return AF_INET;
        else {
            rc = getsockname(fd_, (sockaddr *)&addr, &addr_size);

            //  AF_INET and AF_INET6 can be mixed in select
            //  TODO: If proven otherwise, should simply return addr.sa_family
            if (rc != SOCKET_ERROR)
                return addr.ss_family == AF_INET6 ? AF_INET : addr.ss_family;
        }
    }

    return AF_UNSPEC;
}

zmq::select_t::family_entry_t::family_entry_t () :
    retired (false)
{
}


zmq::select_t::wsa_events_t::wsa_events_t ()
{
    events [0] = WSACreateEvent ();
    wsa_assert (events [0] != WSA_INVALID_EVENT);
    events [1] = WSACreateEvent ();
    wsa_assert (events [1] != WSA_INVALID_EVENT);
    events [2] = WSACreateEvent ();
    wsa_assert (events [2] != WSA_INVALID_EVENT);
    events [3] = WSACreateEvent ();
    wsa_assert (events [3] != WSA_INVALID_EVENT);
}

zmq::select_t::wsa_events_t::~wsa_events_t ()
{
    wsa_assert (WSACloseEvent (events [0]));
    wsa_assert (WSACloseEvent (events [1]));
    wsa_assert (WSACloseEvent (events [2]));
    wsa_assert (WSACloseEvent (events [3]));
}
#endif

#endif
