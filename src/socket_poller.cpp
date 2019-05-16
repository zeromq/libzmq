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
#include "socket_poller.hpp"
#include "err.hpp"
#include "polling_util.hpp"
#include "macros.hpp"

#include <limits.h>

static bool is_thread_safe (zmq::socket_base_t &socket_)
{
    // do not use getsockopt here, since that would fail during context termination
    return socket_.is_thread_safe ();
}

zmq::socket_poller_t::socket_poller_t () :
    _tag (0xCAFEBABE),
    _signaler (NULL)
#if defined ZMQ_POLL_BASED_ON_POLL
    ,
    _pollfds (NULL)
#elif defined ZMQ_POLL_BASED_ON_SELECT
    ,
    _max_fd (0)
#endif
{
    rebuild ();
}

zmq::socket_poller_t::~socket_poller_t ()
{
    //  Mark the socket_poller as dead
    _tag = 0xdeadbeef;

    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        // TODO shouldn't this zmq_assert (it->socket->check_tag ()) instead?
        if (it->socket && it->socket->check_tag ()
            && is_thread_safe (*it->socket)) {
            it->socket->remove_signaler (_signaler);
        }
    }

    if (_signaler != NULL) {
        LIBZMQ_DELETE (_signaler);
    }

#if defined ZMQ_POLL_BASED_ON_POLL
    if (_pollfds) {
        free (_pollfds);
        _pollfds = NULL;
    }
#endif
}

bool zmq::socket_poller_t::check_tag ()
{
    return _tag == 0xCAFEBABE;
}

int zmq::socket_poller_t::signaler_fd (fd_t *fd_)
{
    if (_signaler) {
        *fd_ = _signaler->get_fd ();
        return 0;
    } else {
        // Only thread-safe socket types are guaranteed to have a signaler.
        errno = EINVAL;
        return -1;
    }
}

int zmq::socket_poller_t::add (socket_base_t *socket_,
                               void *user_data_,
                               short events_)
{
    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (it->socket == socket_) {
            errno = EINVAL;
            return -1;
        }
    }

    if (is_thread_safe (*socket_)) {
        if (_signaler == NULL) {
            _signaler = new (std::nothrow) signaler_t ();
            if (!_signaler) {
                errno = ENOMEM;
                return -1;
            }
            if (!_signaler->valid ()) {
                delete _signaler;
                _signaler = NULL;
                errno = EMFILE;
                return -1;
            }
        }

        socket_->add_signaler (_signaler);
    }

    item_t item = {
        socket_,
        0,
        user_data_,
        events_
#if defined ZMQ_POLL_BASED_ON_POLL
        ,
        -1
#endif
    };
    try {
        _items.push_back (item);
    }
    catch (const std::bad_alloc &) {
        errno = ENOMEM;
        return -1;
    }
    _need_rebuild = true;

    return 0;
}

int zmq::socket_poller_t::add_fd (fd_t fd_, void *user_data_, short events_)
{
    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (!it->socket && it->fd == fd_) {
            errno = EINVAL;
            return -1;
        }
    }

    item_t item = {
        NULL,
        fd_,
        user_data_,
        events_
#if defined ZMQ_POLL_BASED_ON_POLL
        ,
        -1
#endif
    };
    try {
        _items.push_back (item);
    }
    catch (const std::bad_alloc &) {
        errno = ENOMEM;
        return -1;
    }
    _need_rebuild = true;

    return 0;
}

int zmq::socket_poller_t::modify (socket_base_t *socket_, short events_)
{
    const items_t::iterator end = _items.end ();
    items_t::iterator it;

    for (it = _items.begin (); it != end; ++it) {
        if (it->socket == socket_)
            break;
    }

    if (it == end) {
        errno = EINVAL;
        return -1;
    }

    it->events = events_;
    _need_rebuild = true;

    return 0;
}


int zmq::socket_poller_t::modify_fd (fd_t fd_, short events_)
{
    const items_t::iterator end = _items.end ();
    items_t::iterator it;

    for (it = _items.begin (); it != end; ++it) {
        if (!it->socket && it->fd == fd_)
            break;
    }

    if (it == end) {
        errno = EINVAL;
        return -1;
    }

    it->events = events_;
    _need_rebuild = true;

    return 0;
}


int zmq::socket_poller_t::remove (socket_base_t *socket_)
{
    const items_t::iterator end = _items.end ();
    items_t::iterator it;

    for (it = _items.begin (); it != end; ++it) {
        if (it->socket == socket_)
            break;
    }

    if (it == end) {
        errno = EINVAL;
        return -1;
    }

    _items.erase (it);
    _need_rebuild = true;

    if (is_thread_safe (*socket_)) {
        socket_->remove_signaler (_signaler);
    }

    return 0;
}

int zmq::socket_poller_t::remove_fd (fd_t fd_)
{
    const items_t::iterator end = _items.end ();
    items_t::iterator it;

    for (it = _items.begin (); it != end; ++it) {
        if (!it->socket && it->fd == fd_)
            break;
    }

    if (it == end) {
        errno = EINVAL;
        return -1;
    }

    _items.erase (it);
    _need_rebuild = true;

    return 0;
}

int zmq::socket_poller_t::rebuild ()
{
    _use_signaler = false;
    _pollset_size = 0;
    _need_rebuild = false;

#if defined ZMQ_POLL_BASED_ON_POLL

    if (_pollfds) {
        free (_pollfds);
        _pollfds = NULL;
    }

    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (it->events) {
            if (it->socket && is_thread_safe (*it->socket)) {
                if (!_use_signaler) {
                    _use_signaler = true;
                    _pollset_size++;
                }
            } else
                _pollset_size++;
        }
    }

    if (_pollset_size == 0)
        return 0;

    _pollfds = static_cast<pollfd *> (malloc (_pollset_size * sizeof (pollfd)));

    if (!_pollfds) {
        errno = ENOMEM;
        _need_rebuild = true;
        return -1;
    }

    int item_nbr = 0;

    if (_use_signaler) {
        item_nbr = 1;
        _pollfds[0].fd = _signaler->get_fd ();
        _pollfds[0].events = POLLIN;
    }

    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (it->events) {
            if (it->socket) {
                if (!is_thread_safe (*it->socket)) {
                    size_t fd_size = sizeof (zmq::fd_t);
                    int rc = it->socket->getsockopt (
                      ZMQ_FD, &_pollfds[item_nbr].fd, &fd_size);
                    zmq_assert (rc == 0);

                    _pollfds[item_nbr].events = POLLIN;
                    item_nbr++;
                }
            } else {
                _pollfds[item_nbr].fd = it->fd;
                _pollfds[item_nbr].events =
                  (it->events & ZMQ_POLLIN ? POLLIN : 0)
                  | (it->events & ZMQ_POLLOUT ? POLLOUT : 0)
                  | (it->events & ZMQ_POLLPRI ? POLLPRI : 0);
                it->pollfd_index = item_nbr;
                item_nbr++;
            }
        }
    }

#elif defined ZMQ_POLL_BASED_ON_SELECT

    //  Ensure we do not attempt to select () on more than FD_SETSIZE
    //  file descriptors.
    zmq_assert (_items.size () <= FD_SETSIZE);

    _pollset_in.resize (_items.size ());
    _pollset_out.resize (_items.size ());
    _pollset_err.resize (_items.size ());

    FD_ZERO (_pollset_in.get ());
    FD_ZERO (_pollset_out.get ());
    FD_ZERO (_pollset_err.get ());

    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (it->socket && is_thread_safe (*it->socket) && it->events) {
            _use_signaler = true;
            FD_SET (_signaler->get_fd (), _pollset_in.get ());
            _pollset_size = 1;
            break;
        }
    }

    _max_fd = 0;

    //  Build the fd_sets for passing to select ().
    for (items_t::iterator it = _items.begin (), end = _items.end (); it != end;
         ++it) {
        if (it->events) {
            //  If the poll item is a 0MQ socket we are interested in input on the
            //  notification file descriptor retrieved by the ZMQ_FD socket option.
            if (it->socket) {
                if (!is_thread_safe (*it->socket)) {
                    zmq::fd_t notify_fd;
                    size_t fd_size = sizeof (zmq::fd_t);
                    int rc =
                      it->socket->getsockopt (ZMQ_FD, &notify_fd, &fd_size);
                    zmq_assert (rc == 0);

                    FD_SET (notify_fd, _pollset_in.get ());
                    if (_max_fd < notify_fd)
                        _max_fd = notify_fd;

                    _pollset_size++;
                }
            }
            //  Else, the poll item is a raw file descriptor. Convert the poll item
            //  events to the appropriate fd_sets.
            else {
                if (it->events & ZMQ_POLLIN)
                    FD_SET (it->fd, _pollset_in.get ());
                if (it->events & ZMQ_POLLOUT)
                    FD_SET (it->fd, _pollset_out.get ());
                if (it->events & ZMQ_POLLERR)
                    FD_SET (it->fd, _pollset_err.get ());
                if (_max_fd < it->fd)
                    _max_fd = it->fd;

                _pollset_size++;
            }
        }
    }

#endif

    return 0;
}

void zmq::socket_poller_t::zero_trail_events (
  zmq::socket_poller_t::event_t *events_, int n_events_, int found_)
{
    for (int i = found_; i < n_events_; ++i) {
        events_[i].socket = NULL;
        events_[i].fd = 0;
        events_[i].user_data = NULL;
        events_[i].events = 0;
    }
}

#if defined ZMQ_POLL_BASED_ON_POLL
int zmq::socket_poller_t::check_events (zmq::socket_poller_t::event_t *events_,
                                        int n_events_)
#elif defined ZMQ_POLL_BASED_ON_SELECT
int zmq::socket_poller_t::check_events (zmq::socket_poller_t::event_t *events_,
                                        int n_events_,
                                        fd_set &inset_,
                                        fd_set &outset_,
                                        fd_set &errset_)
#endif
{
    int found = 0;
    for (items_t::iterator it = _items.begin (), end = _items.end ();
         it != end && found < n_events_; ++it) {
        //  The poll item is a 0MQ socket. Retrieve pending events
        //  using the ZMQ_EVENTS socket option.
        if (it->socket) {
            size_t events_size = sizeof (uint32_t);
            uint32_t events;
            if (it->socket->getsockopt (ZMQ_EVENTS, &events, &events_size)
                == -1) {
                return -1;
            }

            if (it->events & events) {
                events_[found].socket = it->socket;
                events_[found].user_data = it->user_data;
                events_[found].events = it->events & events;
                ++found;
            }
        }
        //  Else, the poll item is a raw file descriptor, simply convert
        //  the events to zmq_pollitem_t-style format.
        else {
#if defined ZMQ_POLL_BASED_ON_POLL

            short revents = _pollfds[it->pollfd_index].revents;
            short events = 0;

            if (revents & POLLIN)
                events |= ZMQ_POLLIN;
            if (revents & POLLOUT)
                events |= ZMQ_POLLOUT;
            if (revents & POLLPRI)
                events |= ZMQ_POLLPRI;
            if (revents & ~(POLLIN | POLLOUT | POLLPRI))
                events |= ZMQ_POLLERR;

#elif defined ZMQ_POLL_BASED_ON_SELECT

            short events = 0;

            if (FD_ISSET (it->fd, &inset_))
                events |= ZMQ_POLLIN;
            if (FD_ISSET (it->fd, &outset_))
                events |= ZMQ_POLLOUT;
            if (FD_ISSET (it->fd, &errset_))
                events |= ZMQ_POLLERR;
#endif //POLL_SELECT

            if (events) {
                events_[found].socket = NULL;
                events_[found].user_data = it->user_data;
                events_[found].fd = it->fd;
                events_[found].events = events;
                ++found;
            }
        }
    }

    return found;
}

//Return 0 if timeout is expired otherwise 1
int zmq::socket_poller_t::adjust_timeout (zmq::clock_t &clock_,
                                          long timeout_,
                                          uint64_t &now_,
                                          uint64_t &end_,
                                          bool &first_pass_)
{
    //  If socket_poller_t::timeout is zero, exit immediately whether there
    //  are events or not.
    if (timeout_ == 0)
        return 0;

    //  At this point we are meant to wait for events but there are none.
    //  If timeout is infinite we can just loop until we get some events.
    if (timeout_ < 0) {
        if (first_pass_)
            first_pass_ = false;
        return 1;
    }

    //  The timeout is finite and there are no events. In the first pass
    //  we get a timestamp of when the polling have begun. (We assume that
    //  first pass have taken negligible time). We also compute the time
    //  when the polling should time out.
    now_ = clock_.now_ms ();
    if (first_pass_) {
        end_ = now_ + timeout_;
        first_pass_ = false;
        return 1;
    }

    //  Find out whether timeout have expired.
    if (now_ >= end_)
        return 0;

    return 1;
}

int zmq::socket_poller_t::wait (zmq::socket_poller_t::event_t *events_,
                                int n_events_,
                                long timeout_)
{
    if (_items.empty () && timeout_ < 0) {
        errno = EFAULT;
        return -1;
    }

    if (_need_rebuild) {
        int rc = rebuild ();
        if (rc == -1)
            return -1;
    }

    if (unlikely (_pollset_size == 0)) {
        // We'll report an error (timed out) as if the list was non-empty and
        // no event occurred within the specified timeout. Otherwise the caller
        // needs to check the return value AND the event to avoid using the
        // nullified event data.
        errno = EAGAIN;
        if (timeout_ == 0)
            return -1;
#if defined ZMQ_HAVE_WINDOWS
        Sleep (timeout_ > 0 ? timeout_ : INFINITE);
        return -1;
#elif defined ZMQ_HAVE_ANDROID
        usleep (timeout_ * 1000);
        return -1;
#elif defined ZMQ_HAVE_OSX
        usleep (timeout_ * 1000);
        errno = EAGAIN;
        return -1;
#elif defined ZMQ_HAVE_VXWORKS
        struct timespec ns_;
        ns_.tv_sec = timeout_ / 1000;
        ns_.tv_nsec = timeout_ % 1000 * 1000000;
        nanosleep (&ns_, 0);
        return -1;
#else
        usleep (timeout_ * 1000);
        return -1;
#endif
    }

#if defined ZMQ_POLL_BASED_ON_POLL
    zmq::clock_t clock;
    uint64_t now = 0;
    uint64_t end = 0;

    bool first_pass = true;

    while (true) {
        //  Compute the timeout for the subsequent poll.
        int timeout;
        if (first_pass)
            timeout = 0;
        else if (timeout_ < 0)
            timeout = -1;
        else
            timeout =
              static_cast<int> (std::min<uint64_t> (end - now, INT_MAX));

        //  Wait for events.
        while (true) {
            int rc = poll (_pollfds, _pollset_size, timeout);
            if (rc == -1 && errno == EINTR) {
                return -1;
            }
            errno_assert (rc >= 0);
            break;
        }

        //  Receive the signal from pollfd
        if (_use_signaler && _pollfds[0].revents & POLLIN)
            _signaler->recv ();

        //  Check for the events.
        int found = check_events (events_, n_events_);
        if (found) {
            if (found > 0)
                zero_trail_events (events_, n_events_, found);
            return found;
        }

        //  Adjust timeout or break
        if (adjust_timeout (clock, timeout_, now, end, first_pass) == 0)
            break;
    }
    errno = EAGAIN;
    return -1;

#elif defined ZMQ_POLL_BASED_ON_SELECT

    zmq::clock_t clock;
    uint64_t now = 0;
    uint64_t end = 0;

    bool first_pass = true;

    optimized_fd_set_t inset (_pollset_size);
    optimized_fd_set_t outset (_pollset_size);
    optimized_fd_set_t errset (_pollset_size);

    while (true) {
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
            memcpy (inset.get (), _pollset_in.get (),
                    valid_pollset_bytes (*_pollset_in.get ()));
            memcpy (outset.get (), _pollset_out.get (),
                    valid_pollset_bytes (*_pollset_out.get ()));
            memcpy (errset.get (), _pollset_err.get (),
                    valid_pollset_bytes (*_pollset_err.get ()));
            const int rc = select (static_cast<int> (_max_fd + 1), inset.get (),
                                   outset.get (), errset.get (), ptimeout);
#if defined ZMQ_HAVE_WINDOWS
            if (unlikely (rc == SOCKET_ERROR)) {
                errno = wsa_error_to_errno (WSAGetLastError ());
                wsa_assert (errno == ENOTSOCK);
                return -1;
            }
#else
            if (unlikely (rc == -1)) {
                errno_assert (errno == EINTR || errno == EBADF);
                return -1;
            }
#endif
            break;
        }

        if (_use_signaler && FD_ISSET (_signaler->get_fd (), inset.get ()))
            _signaler->recv ();

        //  Check for the events.
        const int found = check_events (events_, n_events_, *inset.get (),
                                        *outset.get (), *errset.get ());
        if (found) {
            if (found > 0)
                zero_trail_events (events_, n_events_, found);
            return found;
        }

        //  Adjust timeout or break
        if (adjust_timeout (clock, timeout_, now, end, first_pass) == 0)
            break;
    }

    errno = EAGAIN;
    return -1;

#else

    //  Exotic platforms that support neither poll() nor select().
    errno = ENOTSUP;
    return -1;

#endif
}
