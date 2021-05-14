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
#include "dist.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"
#include "likely.hpp"

zmq::dist_t::dist_t () :
    _matching (0),
    _active (0),
    _eligible (0),
    _more (false)
{
}

zmq::dist_t::~dist_t ()
{
    zmq_assert (_pipes.empty ());
}

void zmq::dist_t::attach (pipe_t *pipe_)
{
    //  If we are in the middle of sending a message, we'll add new pipe
    //  into the list of eligible pipes. Otherwise we add it to the list
    //  of active pipes.
    if (_more) {
        _pipes.push_back (pipe_);
        _pipes.swap (_eligible, _pipes.size () - 1);
        _eligible++;
    } else {
        _pipes.push_back (pipe_);
        _pipes.swap (_active, _pipes.size () - 1);
        _active++;
        _eligible++;
    }
}

bool zmq::dist_t::has_pipe (pipe_t *pipe_)
{
    std::size_t claimed_index = _pipes.index (pipe_);

    // If pipe claims to be outside the available index space it can't be in the distributor.
    if (claimed_index >= _pipes.size ()) {
        return false;
    }

    return _pipes[claimed_index] == pipe_;
}

void zmq::dist_t::match (pipe_t *pipe_)
{
    //  If pipe is already matching do nothing.
    if (_pipes.index (pipe_) < _matching)
        return;

    //  If the pipe isn't eligible, ignore it.
    if (_pipes.index (pipe_) >= _eligible)
        return;

    //  Mark the pipe as matching.
    _pipes.swap (_pipes.index (pipe_), _matching);
    _matching++;
}

void zmq::dist_t::reverse_match ()
{
    const pipes_t::size_type prev_matching = _matching;

    // Reset matching to 0
    unmatch ();

    // Mark all matching pipes as not matching and vice-versa.
    // To do this, push all pipes that are eligible but not
    // matched - i.e. between "matching" and "eligible" -
    // to the beginning of the queue.
    for (pipes_t::size_type i = prev_matching; i < _eligible; ++i) {
        _pipes.swap (i, _matching++);
    }
}

void zmq::dist_t::unmatch ()
{
    _matching = 0;
}

void zmq::dist_t::pipe_terminated (pipe_t *pipe_)
{
    //  Remove the pipe from the list; adjust number of matching, active and/or
    //  eligible pipes accordingly.
    if (_pipes.index (pipe_) < _matching) {
        _pipes.swap (_pipes.index (pipe_), _matching - 1);
        _matching--;
    }
    if (_pipes.index (pipe_) < _active) {
        _pipes.swap (_pipes.index (pipe_), _active - 1);
        _active--;
    }
    if (_pipes.index (pipe_) < _eligible) {
        _pipes.swap (_pipes.index (pipe_), _eligible - 1);
        _eligible--;
    }

    _pipes.erase (pipe_);
}

void zmq::dist_t::activated (pipe_t *pipe_)
{
    //  Move the pipe from passive to eligible state.
    if (_eligible < _pipes.size ()) {
        _pipes.swap (_pipes.index (pipe_), _eligible);
        _eligible++;
    }

    //  If there's no message being sent at the moment, move it to
    //  the active state.
    if (!_more && _active < _pipes.size ()) {
        _pipes.swap (_eligible - 1, _active);
        _active++;
    }
}

int zmq::dist_t::send_to_all (msg_t *msg_)
{
    _matching = _active;
    return send_to_matching (msg_);
}

int zmq::dist_t::send_to_matching (msg_t *msg_)
{
    //  Is this end of a multipart message?
    const bool msg_more = (msg_->flags () & msg_t::more) != 0;

    //  Push the message to matching pipes.
    distribute (msg_);

    //  If multipart message is fully sent, activate all the eligible pipes.
    if (!msg_more)
        _active = _eligible;

    _more = msg_more;

    return 0;
}

void zmq::dist_t::distribute (msg_t *msg_)
{
    //  If there are no matching pipes available, simply drop the message.
    if (_matching == 0) {
        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
        return;
    }

    if (msg_->is_vsm ()) {
        for (pipes_t::size_type i = 0; i < _matching;) {
            if (!write (_pipes[i], msg_)) {
                //  Use same index again because entry will have been removed.
            } else {
                ++i;
            }
        }
        int rc = msg_->init ();
        errno_assert (rc == 0);
        return;
    }

    //  Add matching-1 references to the message. We already hold one reference,
    //  that's why -1.
    msg_->add_refs (static_cast<int> (_matching) - 1);

    //  Push copy of the message to each matching pipe.
    int failed = 0;
    for (pipes_t::size_type i = 0; i < _matching;) {
        if (!write (_pipes[i], msg_)) {
            ++failed;
            //  Use same index again because entry will have been removed.
        } else {
            ++i;
        }
    }
    if (unlikely (failed))
        msg_->rm_refs (failed);

    //  Detach the original message from the data buffer. Note that we don't
    //  close the message. That's because we've already used all the references.
    const int rc = msg_->init ();
    errno_assert (rc == 0);
}

bool zmq::dist_t::has_out ()
{
    return true;
}

bool zmq::dist_t::write (pipe_t *pipe_, msg_t *msg_)
{
    if (!pipe_->write (msg_)) {
        _pipes.swap (_pipes.index (pipe_), _matching - 1);
        _matching--;
        _pipes.swap (_pipes.index (pipe_), _active - 1);
        _active--;
        _pipes.swap (_active, _eligible - 1);
        _eligible--;
        return false;
    }
    if (!(msg_->flags () & msg_t::more))
        pipe_->flush ();
    return true;
}

bool zmq::dist_t::check_hwm ()
{
    for (pipes_t::size_type i = 0; i < _matching; ++i)
        if (!_pipes[i]->check_hwm ())
            return false;

    return true;
}
