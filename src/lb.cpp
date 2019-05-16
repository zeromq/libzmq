/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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
#include "lb.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

zmq::lb_t::lb_t () : _active (0), _current (0), _more (false), _dropping (false)
{
}

zmq::lb_t::~lb_t ()
{
    zmq_assert (_pipes.empty ());
}

void zmq::lb_t::attach (pipe_t *pipe_)
{
    _pipes.push_back (pipe_);
    activated (pipe_);
}

void zmq::lb_t::pipe_terminated (pipe_t *pipe_)
{
    pipes_t::size_type index = _pipes.index (pipe_);

    //  If we are in the middle of multipart message and current pipe
    //  have disconnected, we have to drop the remainder of the message.
    if (index == _current && _more)
        _dropping = true;

    //  Remove the pipe from the list; adjust number of active pipes
    //  accordingly.
    if (index < _active) {
        _active--;
        _pipes.swap (index, _active);
        if (_current == _active)
            _current = 0;
    }
    _pipes.erase (pipe_);
}

void zmq::lb_t::activated (pipe_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    _pipes.swap (_pipes.index (pipe_), _active);
    _active++;
}

int zmq::lb_t::send (msg_t *msg_)
{
    return sendpipe (msg_, NULL);
}

int zmq::lb_t::sendpipe (msg_t *msg_, pipe_t **pipe_)
{
    //  Drop the message if required. If we are at the end of the message
    //  switch back to non-dropping mode.
    if (_dropping) {
        _more = (msg_->flags () & msg_t::more) != 0;
        _dropping = _more;

        int rc = msg_->close ();
        errno_assert (rc == 0);
        rc = msg_->init ();
        errno_assert (rc == 0);
        return 0;
    }

    while (_active > 0) {
        if (_pipes[_current]->write (msg_)) {
            if (pipe_)
                *pipe_ = _pipes[_current];
            break;
        }

        // If send fails for multi-part msg rollback other
        // parts sent earlier and return EAGAIN.
        // Application should handle this as suitable
        if (_more) {
            _pipes[_current]->rollback ();
            // At this point the pipe is already being deallocated
            // and the first N frames are unreachable (_outpipe is
            // most likely already NULL so rollback won't actually do
            // anything and they can't be un-written to deliver later).
            // Return EFAULT to socket_base caller to drop current message
            // and any other subsequent frames to avoid them being
            // "stuck" and received when a new client reconnects, which
            // would break atomicity of multi-part messages (in blocking mode
            // socket_base just tries again and again to send the same message)
            // Note that given dropping mode returns 0, the user will
            // never know that the message could not be delivered, but
            // can't really fix it without breaking backward compatibility.
            // -2/EAGAIN will make sure socket_base caller does not re-enter
            // immediately or after a short sleep in blocking mode.
            _dropping = (msg_->flags () & msg_t::more) != 0;
            _more = false;
            errno = EAGAIN;
            return -2;
        }

        _active--;
        if (_current < _active)
            _pipes.swap (_current, _active);
        else
            _current = 0;
    }

    //  If there are no pipes we cannot send the message.
    if (_active == 0) {
        errno = EAGAIN;
        return -1;
    }

    //  If it's final part of the message we can flush it downstream and
    //  continue round-robining (load balance).
    _more = (msg_->flags () & msg_t::more) != 0;
    if (!_more) {
        _pipes[_current]->flush ();

        if (++_current >= _active)
            _current = 0;
    }

    //  Detach the message from the data buffer.
    int rc = msg_->init ();
    errno_assert (rc == 0);

    return 0;
}

bool zmq::lb_t::has_out ()
{
    //  If one part of the message was already written we can definitely
    //  write the rest of the message.
    if (_more)
        return true;

    while (_active > 0) {
        //  Check whether a pipe has room for another message.
        if (_pipes[_current]->check_write ())
            return true;

        //  Deactivate the pipe.
        _active--;
        _pipes.swap (_current, _active);
        if (_current == _active)
            _current = 0;
    }

    return false;
}
