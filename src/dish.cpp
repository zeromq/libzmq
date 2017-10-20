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
    std::string group = std::string (group_);

    if (group.length () > ZMQ_GROUP_MAX_LENGTH) {
        errno = EINVAL;
        return -1;
    }

    subscriptions_t::iterator it = subscriptions.find (group);

    //  User cannot join same group twice
    if (it != subscriptions.end ()) {
        errno = EINVAL;
        return -1;
    }

    subscriptions.insert (group);

    msg_t msg;
    int rc = msg.init_join ();
    errno_assert (rc == 0);

    rc = msg.set_group (group_);
    errno_assert (rc == 0);

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
    std::string group = std::string (group_);

    if (group.length () > ZMQ_GROUP_MAX_LENGTH) {
        errno = EINVAL;
        return -1;
    }

    subscriptions_t::iterator it =  std::find (subscriptions.begin (), subscriptions.end (), group);

    if (it == subscriptions.end ()) {
        errno = EINVAL;
        return -1;
    }

    subscriptions.erase (it);

    msg_t msg;
    int rc = msg.init_leave ();
    errno_assert (rc == 0);

    rc = msg.set_group (group_);
    errno_assert (rc == 0);

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
    LIBZMQ_UNUSED (msg_);
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

    while (true) {

        //  Get a message using fair queueing algorithm.
        int rc = fq.recv (msg_);

        //  If there's no message available, return immediately.
        //  The same when error occurs.
        if (rc != 0)
            return -1;

        //  Filtering non matching messages
        subscriptions_t::iterator it = subscriptions.find (std::string(msg_->group ()));
        if (it != subscriptions.end ())
            return 0;
    }
}

bool zmq::dish_t::xhas_in ()
{
    //  If there's already a message prepared by a previous call to zmq_poll,
    //  return straight ahead.
    if (has_message)
        return true;

    while (true) {
        //  Get a message using fair queueing algorithm.
        int rc = fq.recv (&message);

        //  If there's no message available, return immediately.
        //  The same when error occurs.
        if (rc != 0) {
            errno_assert (errno == EAGAIN);
            return false;
        }

        //  Filtering non matching messages
        subscriptions_t::iterator it = subscriptions.find (std::string(message.group ()));
        if (it != subscriptions.end ()) {
            has_message = true;
            return true;
        }
    }
}

const zmq::blob_t &zmq::dish_t::get_credential () const
{
    return fq.get_credential ();
}

void zmq::dish_t::send_subscriptions (pipe_t *pipe_)
{
    for (subscriptions_t::iterator it = subscriptions.begin (); it != subscriptions.end (); ++it) {
        msg_t msg;
        int rc = msg.init_join ();
        errno_assert (rc == 0);

        rc = msg.set_group (it->c_str());
        errno_assert (rc == 0);

        //  Send it to the pipe.
        pipe_->write (&msg);
        msg.close ();
    }

    pipe_->flush ();
}

zmq::dish_session_t::dish_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      address_t *addr_) :
    session_base_t (io_thread_, connect_, socket_, options_, addr_),
    state (group)
{
}

zmq::dish_session_t::~dish_session_t ()
{
}

int zmq::dish_session_t::push_msg (msg_t *msg_)
{
    if (state == group) {
        if ((msg_->flags() & msg_t::more) != msg_t::more) {
            errno = EFAULT;
            return -1;
        }

        if (msg_->size() > ZMQ_GROUP_MAX_LENGTH) {
            errno = EFAULT;
            return -1;
        }

        group_msg = *msg_;
        state = body;

        int rc = msg_->init ();
        errno_assert (rc == 0);
        return 0;
    }
    else {
        //  Set the message group
        int rc = msg_->set_group ((char*)group_msg.data (), group_msg. size());
        errno_assert (rc == 0);

        //  We set the group, so we don't need the group_msg anymore
        rc = group_msg.close ();
        errno_assert (rc == 0);

        //  Thread safe socket doesn't support multipart messages
        if ((msg_->flags() & msg_t::more) == msg_t::more) {
            errno = EFAULT;
            return -1;
        }

        //  Push message to dish socket
        rc = session_base_t::push_msg (msg_);

        if (rc == 0)
            state = group;

        return rc;
    }
}

int zmq::dish_session_t::pull_msg (msg_t *msg_)
{
    int rc = session_base_t::pull_msg (msg_);

    if (rc != 0)
        return rc;

    if (!msg_->is_join () && !msg_->is_leave ())
        return rc;
    else {
        int group_length = (int) strlen (msg_->group ());

        msg_t command;
        int offset;

        if (msg_->is_join ()) {
            rc = command.init_size (group_length + 5);
            errno_assert(rc == 0);
            offset = 5;
            memcpy (command.data (), "\4JOIN", 5);
        }
        else {
            rc = command.init_size (group_length + 6);
            errno_assert(rc == 0);
            offset = 6;
            memcpy (command.data (), "\5LEAVE", 6);
        }

        command.set_flags (msg_t::command);
        char* command_data = (char*)command.data ();

        //  Copy the group
        memcpy (command_data + offset, msg_->group (), group_length);

        //  Close the join message
        rc = msg_->close ();
        errno_assert (rc == 0);

        *msg_ = command;

        return 0;
    }
}

void zmq::dish_session_t::reset ()
{
    session_base_t::reset ();
    state = group;
}
