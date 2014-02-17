/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

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
