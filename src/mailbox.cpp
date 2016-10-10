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
#include "mailbox.hpp"
#include "err.hpp"

zmq::mailbox_t::mailbox_t ()
{
    //  Get the pipe into passive state. That way, if the users starts by
    //  polling on the associated file descriptor it will get woken up when
    //  new command is posted.
    const bool ok = cpipe.read (NULL);
    zmq_assert (!ok);
    active = false;
}

zmq::mailbox_t::~mailbox_t ()
{
    //  TODO: Retrieve and deallocate commands inside the cpipe.

    // Work around problem that other threads might still be in our
    // send() method, by waiting on the mutex before disappearing.
    sync.lock ();
    sync.unlock ();
}

zmq::fd_t zmq::mailbox_t::get_fd () const
{
    return signaler.get_fd ();
}

void zmq::mailbox_t::send (const command_t &cmd_)
{
    sync.lock ();
    cpipe.write (cmd_, false);
    const bool ok = cpipe.flush ();
    sync.unlock ();
    if (!ok)
        signaler.send ();
}

int zmq::mailbox_t::recv (command_t *cmd_, int timeout_)
{
    //  Try to get the command straight away.
    if (active) {
        if (cpipe.read (cmd_))
            return 0;

        //  If there are no more commands available, switch into passive state.
        active = false;
    }

    //  Wait for signal from the command sender.
    int rc = signaler.wait (timeout_);
    if (rc == -1) {
        errno_assert (errno == EAGAIN || errno == EINTR);
        return -1;
    }

    //  Receive the signal.
    rc = signaler.recv_failable ();
    if (rc == -1) {
        errno_assert (errno == EAGAIN);
        return -1;
    }

    //  Switch into active state.
    active = true;

    //  Get a command.
    const bool ok = cpipe.read (cmd_);
    zmq_assert (ok);
    return 0;
}
