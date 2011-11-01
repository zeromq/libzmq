/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#if defined ZMQ_FORCE_SELECT
#define ZMQ_USE_SELECT
#include "select.hpp"
#elif defined ZMQ_FORCE_POLL
#define ZMQ_USE_POLL
#include "poll.hpp"
#elif defined ZMQ_FORCE_EPOLL
#define ZMQ_USE_EPOLL
#include "epoll.hpp"
#elif defined ZMQ_FORCE_DEVPOLL
#define ZMQ_USE_DEVPOLL
#include "devpoll.hpp"
#elif defined ZMQ_FORCE_KQUEUE
#define ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_HAVE_LINUX
#define ZMQ_USE_EPOLL
#include "epoll.hpp"
#elif defined ZMQ_HAVE_WINDOWS
#define ZMQ_USE_SELECT
#include "select.hpp"
#elif defined ZMQ_HAVE_FREEBSD
#define ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_HAVE_OPENBSD
#define ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_HAVE_NETBSD
#define ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_HAVE_SOLARIS
#define ZMQ_USE_DEVPOLL
#include "devpoll.hpp"
#elif defined ZMQ_HAVE_OSX
#define ZMQ_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_HAVE_QNXNTO
#define ZMQ_USE_POLL
#include "poll.hpp"
#elif defined ZMQ_HAVE_AIX
#define ZMQ_USE_POLL
#include "poll.hpp"
#elif defined ZMQ_HAVE_HPUX
#define ZMQ_USE_DEVPOLL
#include "devpoll.hpp"
#elif defined ZMQ_HAVE_OPENVMS
#define ZMQ_USE_SELECT
#include "select.hpp"
#elif defined ZMQ_HAVE_CYGWIN
#define ZMQ_USE_SELECT
#include "select.hpp"
#else
#error Unsupported platform
#endif

#endif
