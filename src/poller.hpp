/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_POLLER_HPP_INCLUDED__
#define __ZMQ_POLLER_HPP_INCLUDED__

#if defined ZMQ_IOTHREAD_POLLER_USE_KQUEUE                                     \
    + defined ZMQ_IOTHREAD_POLLER_USE_EPOLL                                    \
    + defined ZMQ_IOTHREAD_POLLER_USE_DEVPOLL                                  \
    + defined ZMQ_IOTHREAD_POLLER_USE_POLLSET                                  \
    + defined ZMQ_IOTHREAD_POLLER_POLL                                         \
    + defined ZMQ_IOTHREAD_POLLER_USE_SELECT                                   \
  > 1
#error More than one of the ZMQ_IOTHREAD_POLLER_USE_* macros defined
#endif

#if defined ZMQ_IOTHREAD_POLLER_USE_KQUEUE
#include "kqueue.hpp"
#elif defined ZMQ_IOTHREAD_POLLER_USE_EPOLL
#include "epoll.hpp"
#elif defined ZMQ_IOTHREAD_POLLER_USE_DEVPOLL
#include "devpoll.hpp"
#elif defined ZMQ_IOTHREAD_POLLER_USE_POLLSET
#include "pollset.hpp"
#elif defined ZMQ_IOTHREAD_POLLER_USE_POLL
#include "poll.hpp"
#elif defined ZMQ_IOTHREAD_POLLER_USE_SELECT
#include "select.hpp"
#elif defined ZMQ_HAVE_GNU
#define ZMQ_IOTHREAD_POLLER_USE_POLL
#include "poll.hpp"
#else
#error None of the ZMQ_IOTHREAD_POLLER_USE_* macros defined
#endif

#if (defined ZMQ_POLL_BASED_ON_SELECT + defined ZMQ_POLL_BASED_ON_POLL) > 1
#error More than one of the ZMQ_POLL_BASED_ON_* macros defined
#elif (defined ZMQ_POLL_BASED_ON_SELECT + defined ZMQ_POLL_BASED_ON_POLL) == 0
#error None of the ZMQ_POLL_BASED_ON_* macros defined
#endif

#endif
