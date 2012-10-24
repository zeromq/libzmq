/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

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

#include <stddef.h>
#include "platform.hpp"
#include "proxy.hpp"
#include "likely.hpp"

#if defined ZMQ_FORCE_SELECT
#define ZMQ_POLL_BASED_ON_SELECT
#elif defined ZMQ_FORCE_POLL
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OPENBSD || defined ZMQ_HAVE_SOLARIS ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_QNXNTO ||\
    defined ZMQ_HAVE_HPUX || defined ZMQ_HAVE_AIX ||\
    defined ZMQ_HAVE_NETBSD
#define ZMQ_POLL_BASED_ON_POLL
#elif defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS ||\
     defined ZMQ_HAVE_CYGWIN
#define ZMQ_POLL_BASED_ON_SELECT
#endif

//  On AIX platform, poll.h has to be included first to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
#if defined ZMQ_POLL_BASED_ON_POLL
#include <poll.h>
#endif

// These headers end up pulling in zmq.h somewhere in their include
// dependency chain
#include "socket_base.hpp"
#include "err.hpp"

// zmq.h must be included *after* poll.h for AIX to build properly
#include "../include/zmq.h"


int zmq::proxy (
    class socket_base_t *frontend_,
    class socket_base_t *backend_,
    class socket_base_t *capture_)
{
    msg_t msg;
    int rc = msg.init ();
    if (rc != 0)
        return -1;

    //  The algorithm below assumes ratio of requests and replies processed
    //  under full load to be 1:1.

    int more;
    size_t moresz;
    zmq_pollitem_t items [] = {
        { frontend_, 0, ZMQ_POLLIN, 0 },
        { backend_, 0, ZMQ_POLLIN, 0 }
    };
    while (true) {
        //  Wait while there are either requests or replies to process.
        rc = zmq_poll (&items [0], 2, -1);
        if (unlikely (rc < 0))
            return -1;

        //  Process a request
        if (items [0].revents & ZMQ_POLLIN) {
            while (true) {
                rc = frontend_->recv (&msg, 0);
                if (unlikely (rc < 0))
                    return -1;

                moresz = sizeof more;
                rc = frontend_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
                if (unlikely (rc < 0))
                    return -1;

                //  Copy message to capture socket if any
                if (capture_) {
                    msg_t ctrl;
                    rc = ctrl.init ();
                    if (unlikely (rc < 0))
                        return -1;
                    rc = ctrl.copy (msg);
                    if (unlikely (rc < 0))
                        return -1;
                    rc = capture_->send (&ctrl, more? ZMQ_SNDMORE: 0);
                    if (unlikely (rc < 0))
                        return -1;
                }
                rc = backend_->send (&msg, more? ZMQ_SNDMORE: 0);
                if (unlikely (rc < 0))
                    return -1;
                if (more == 0)
                    break;
            }
        }
        //  Process a reply
        if (items [1].revents & ZMQ_POLLIN) {
            while (true) {
                rc = backend_->recv (&msg, 0);
                if (unlikely (rc < 0))
                    return -1;

                moresz = sizeof more;
                rc = backend_->getsockopt (ZMQ_RCVMORE, &more, &moresz);
                if (unlikely (rc < 0))
                    return -1;

                //  Copy message to capture socket if any
                if (capture_) {
                    msg_t ctrl;
                    rc = ctrl.init ();
                    if (unlikely (rc < 0))
                        return -1;
                    rc = ctrl.copy (msg);
                    if (unlikely (rc < 0))
                        return -1;
                    rc = capture_->send (&ctrl, more? ZMQ_SNDMORE: 0);
                    if (unlikely (rc < 0))
                        return -1;
                }
                rc = frontend_->send (&msg, more? ZMQ_SNDMORE: 0);
                if (unlikely (rc < 0))
                    return -1;
                if (more == 0)
                    break;
            }
        }

    }
    return 0;
}
