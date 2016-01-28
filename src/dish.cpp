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

#include <string.h>

#include "macros.hpp"
#include "dish.hpp"
#include "err.hpp"

zmq::dish_t::dish_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true),
    has_message (false)
{
    options.type = ZMQ_DISH;

    //  When socket is being closed down we don't want to wait till pending
    //  subscription commands are sent to the wire.
    options.linger = 0;

    int rc = message.init ();
    errno_assert (rc == 0);
}

zmq::dish_t::~dish_t ()
{
    int rc = message.close ();
    errno_assert (rc == 0);
}

void zmq::dish_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);

    zmq_assert (pipe_);
    fq.attach (pipe_);
    dist.attach (pipe_);

    //  Send all the cached subscriptions to the new upstream peer.
    send_subscriptions (pipe_);
}

void zmq::dish_t::xread_activated (pipe_t *pipe_)
{
    fq.activated (pipe_);
}

void zmq::dish_t::xwrite_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

void zmq::dish_t::xpipe_terminated (pipe_t *pipe_)
{
    fq.pipe_terminated (pipe_);
    dist.pipe_terminated (pipe_);
}

void zmq::dish_t::xhiccuped (pipe_t *pipe_)
{
    //  Send all the cached subscriptions to the hiccuped pipe.
    send_subscriptions (pipe_);
}

int zmq::dish_t::xjoin (const char* group_)
{
    if (strlen (group_) > ZMQ_GROUP_MAX_LENGTH) {
        errno = EINVAL;
        return -1;
    }

    subscriptions_t::iterator it =
        std::find (subscriptions.begin (), subscriptions.end (), std::string(group_));

    //  User cannot join same group twice
    if (it != subscriptions.end ()) {
        errno = EINVAL;
        return -1;
    }

    subscriptions.push_back (std::string (group_));

    size_t len = strlen (group_);
    msg_t msg;
    int rc = msg.init_size (len + 1);
    errno_assert (rc == 0);

    char *data = (char*) msg.data ();
    data[0] = 'J';
    memcpy (data + 1, group_, len);

    int err = 0;
    rc = dist.send_to_all (&msg);
    if (rc != 0)
        err = errno;
    int rc2 = msg.close ();
    errno_assert (rc2 == 0);
    if (rc != 0)
        errno = err;
    return rc;
}

int zmq::dish_t::xleave (const char* group_)
{
    if (strlen (group_) > ZMQ_GROUP_MAX_LENGTH) {
        errno = EINVAL;
        return -1;
    }

    subscriptions_t::iterator it =  std::find (subscriptions.begin (), subscriptions.end (), std::string (group_));

    if (it == subscriptions.end ()) {
        errno = EINVAL;
        return -1;
    }

    subscriptions.erase (it);

    size_t len = strlen (group_);
    msg_t msg;
    int rc = msg.init_size (len + 1);
    errno_assert (rc == 0);

    char *data = (char*) msg.data ();
    data[0] = 'L';
    memcpy (data + 1, group_, len);

    int err = 0;
    rc = dist.send_to_all (&msg);
    if (rc != 0)
        err = errno;
    int rc2 = msg.close ();
    errno_assert (rc2 == 0);
    if (rc != 0)
        errno = err;
    return rc;
}

int zmq::dish_t::xsend (msg_t *msg_)
{
    errno = ENOTSUP;
    return -1;
}

bool zmq::dish_t::xhas_out ()
{
    //  Subscription can be added/removed anytime.
    return true;
}

int zmq::dish_t::xrecv (msg_t *msg_)
{
    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return it straight ahead.
    if (has_message) {
        int rc = msg_->move (message);
        errno_assert (rc == 0);
        has_message = false;
        return 0;
    }

    //  Get a message using fair queueing algorithm.
    int rc = fq.recv (msg_);

    //  If there's no message available, return immediately.
    //  The same when error occurs.
    if (rc != 0)
        return -1;

    return 0;
}

bool zmq::dish_t::xhas_in ()
{
    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return straight ahead.
    if (has_message)
        return true;

    //  Get a message using fair queueing algorithm.
    int rc = fq.recv (&message);

    //  If there's no message available, return immediately.
    //  The same when error occurs.
    if (rc != 0) {
        errno_assert (errno == EAGAIN);
        return false;
    }

    has_message = true;
    return true;
}

zmq::blob_t zmq::dish_t::get_credential () const
{
    return fq.get_credential ();
}

void zmq::dish_t::send_subscriptions (pipe_t *pipe_)
{
    for (subscriptions_t::iterator it = subscriptions.begin (); it != subscriptions.end (); ++it) {
        msg_t msg;
        int rc = msg.init_size (it->length () + 1);
        errno_assert (rc == 0);
        char *data = (char*) msg.data ();
        data [0] = 'J';
        it->copy (data + 1, it->length ());

        //  Send it to the pipe.
        bool sent = pipe_->write (&msg);

        //  If we reached the SNDHWM, and thus cannot send the subscription, drop
        //  the subscription message instead. This matches the behaviour of
        //  zmq_setsockopt(ZMQ_SUBSCRIBE, ...), which also drops subscriptions
        //  when the SNDHWM is reached.
        if (!sent)
            msg.close ();
    }

    pipe_->flush ();
}
