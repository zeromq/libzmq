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

#include "radio.hpp"
#include "macros.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::radio_t::radio_t (class ctx_t *parent_, uint32_t tid_, int sid_) :
    socket_base_t (parent_, tid_, sid_, true)
{
    options.type = ZMQ_RADIO;
}

zmq::radio_t::~radio_t ()
{
}

void zmq::radio_t::xattach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    LIBZMQ_UNUSED (subscribe_to_all_);

    zmq_assert (pipe_);

    //  Don't delay pipe termination as there is no one
    //  to receive the delimiter.
    pipe_->set_nodelay ();

    dist.attach (pipe_);

    //  The pipe is active when attached. Let's read the subscriptions from
    //  it, if any.
    xread_activated (pipe_);
}

void zmq::radio_t::xread_activated (pipe_t *pipe_)
{
    //  There are some subscriptions waiting. Let's process them.
    msg_t sub;
    while (pipe_->read (&sub)) {
        //  Apply the subscription to the trie
        const char * data = (char *) sub.data ();
        const size_t size = sub.size ();
        if (size > 0 && (*data == 'J' || *data == 'L')) {
            std::string group = std::string (data + 1, sub. size() - 1);

            if (*data == 'J')
                subscriptions.insert (subscriptions_t::value_type (group, pipe_));
            else {
                std::pair<subscriptions_t::iterator, subscriptions_t::iterator> range =
                    subscriptions.equal_range (group);

                for (subscriptions_t::iterator it = range.first; it != range.second; ++it) {
                    if (it->second == pipe_) {
                        subscriptions.erase (it);
                        break;
                    }
                }
            }
        }
        sub.close ();
    }
}

void zmq::radio_t::xwrite_activated (pipe_t *pipe_)
{
    dist.activated (pipe_);
}

void zmq::radio_t::xpipe_terminated (pipe_t *pipe_)
{
    for (subscriptions_t::iterator it = subscriptions.begin (); it != subscriptions.end (); ++it) {
        if (it->second == pipe_) {
            subscriptions.erase (it);
        }
    }

    dist.pipe_terminated (pipe_);
}

int zmq::radio_t::xsend (msg_t *msg_)
{
    //  Radio sockets do not allow multipart data (ZMQ_SNDMORE)
    if (msg_->flags () & msg_t::more) {
        errno = EINVAL;
        return -1;
    }

    dist.unmatch ();

    std::pair<subscriptions_t::iterator, subscriptions_t::iterator> range =
        subscriptions.equal_range (std::string(msg_->group ()));

    for (subscriptions_t::iterator it = range.first; it != range.second; ++it)
        dist.match (it-> second);

    int rc = dist.send_to_matching (msg_);

    return rc;
}

bool zmq::radio_t::xhas_out ()
{
    return dist.has_out ();
}

int zmq::radio_t::xrecv (msg_t *msg_)
{
    //  Messages cannot be received from PUB socket.
    errno = ENOTSUP;
    return -1;
}

bool zmq::radio_t::xhas_in ()
{
    return false;
}

zmq::radio_session_t::radio_session_t (io_thread_t *io_thread_, bool connect_,
      socket_base_t *socket_, const options_t &options_,
      address_t *addr_) :
    session_base_t (io_thread_, connect_, socket_, options_, addr_),
    state (group)
{
}

zmq::radio_session_t::~radio_session_t ()
{
}

int zmq::radio_session_t::pull_msg (msg_t *msg_)
{
    if (state == group) {
        int rc = session_base_t::pull_msg (&pending_msg);
        if (rc != 0)
            return rc;

        const char *group = pending_msg.group ();
        int length = strlen (group);

        //  First frame is the group
        msg_->init_size (length);
        msg_->set_flags (msg_t::more);
        memcpy (msg_->data (), group, length);

        //  Next status is the body
        state = body;
        return 0;
    }
    else {
        *msg_ = pending_msg;
        state = group;
        return 0;
    }
}

void zmq::radio_session_t::reset ()
{
    session_base_t::reset ();
    state = group;
}
