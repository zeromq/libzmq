/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_POLLER_HPP_INCLUDED__
#define __ZMQ_POLLER_HPP_INCLUDED__

#include "platform.hpp"

#if   defined ZMQ_USE_KQUEUE  + defined ZMQ_USE_EPOLL \
    + defined ZMQ_USE_DEVPOLL + defined ZMQ_USE_POLL  \
    + defined ZMQ_USE_SELECT > 1
#error More than one of the ZMQ_USE_* macros defined
#endif

#if defined ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_USE_EPOLL
#include "epoll.hpp"
#elif defined ZMQ_USE_DEVPOLL
#include "devpoll.hpp"
#elif defined ZMQ_USE_POLL
#include "poll.hpp"
#elif defined ZMQ_USE_SELECT
#include "select.hpp"
#else
#error None of the ZMQ_USE_* macros defined
#endif

#if defined ZMQ_USE_SELECT
#define ZMQ_POLL_BASED_ON_SELECT
#else
#define ZMQ_POLL_BASED_ON_POLL
#endif

#endif
