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
#include "../include/zmq.h"
#include "platform.hpp"
#include "proxy.hpp"
#include "socket_base.hpp"
#include "likely.hpp"
#include "err.hpp"

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
