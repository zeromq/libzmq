/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include "mailbox_safe.hpp"
#include "clock.hpp"
#include "err.hpp"

zmq::mailbox_safe_t::mailbox_safe_t (mutex_t* sync_) :
    sync (sync_)
{
    //  Get the pipe into passive state. That way, if the users starts by
    //  polling on the associated file descriptor it will get woken up when
    //  new command is posted.
    const bool ok = cpipe.read (NULL);
    zmq_assert (!ok);
}

zmq::mailbox_safe_t::~mailbox_safe_t ()
{
    //  TODO: Retrieve and deallocate commands inside the cpipe.

    // Work around problem that other threads might still be in our
    // send() method, by waiting on the mutex before disappearing.
    sync->lock ();
    sync->unlock ();
}

void zmq::mailbox_safe_t::add_signaler(signaler_t* signaler)
{
    signalers.push_back(signaler);
}

void zmq::mailbox_safe_t::remove_signaler(signaler_t* signaler)
{
    std::vector<signaler_t*>::iterator it = signalers.begin();

    // TODO: make a copy of array and signal outside the lock
    for (; it != signalers.end(); ++it){
        if (*it == signaler)
           break;        
    }

    if (it != signalers.end())
        signalers.erase(it);
}

void zmq::mailbox_safe_t::send (const command_t &cmd_)
{
    sync->lock ();
    cpipe.write (cmd_, false);
    const bool ok = cpipe.flush ();

    if (!ok) {
        cond_var.broadcast ();
        for (std::vector<signaler_t*>::iterator it = signalers.begin(); it != signalers.end(); ++it){
            (*it)->send();
        }
    }

    sync->unlock ();
}

int zmq::mailbox_safe_t::recv (command_t *cmd_, int timeout_)
{
    //  Try to get the command straight away.
    if (cpipe.read (cmd_))
        return 0;
    
    //  Wait for signal from the command sender.
    int rc = cond_var.wait (sync, timeout_);
    if (rc == -1) {
        errno_assert (errno == EAGAIN || errno == EINTR);
        return -1;
    }

    //  Another thread may already fetch the command
    const bool ok = cpipe.read (cmd_);

    if (!ok) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}
