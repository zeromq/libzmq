/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include "reaper.hpp"
#include "socket_base.hpp"
#include "err.hpp"

zmq::reaper_t::reaper_t (class ctx_t *ctx_, uint32_t tid_) :
    object_t (ctx_, tid_),
    sockets (0),
    terminating (false)
{
    poller = new (std::nothrow) poller_t (*ctx_);
    alloc_assert (poller);

    mailbox_handle = poller->add_fd (mailbox.get_fd (), this);
    poller->set_pollin (mailbox_handle);

#ifdef HAVE_FORK
    pid = getpid();
#endif
}

zmq::reaper_t::~reaper_t ()
{
    delete poller;
}

zmq::mailbox_t *zmq::reaper_t::get_mailbox ()
{
    return &mailbox;
}

void zmq::reaper_t::start ()
{
    //  Start the thread.
    poller->start ();
}

void zmq::reaper_t::stop ()
{
    send_stop ();
}

void zmq::reaper_t::in_event ()
{
    while (true) {
#ifdef HAVE_FORK
        if (unlikely(pid != getpid()))
        {
            //printf("zmq::reaper_t::in_event return in child process %d\n", (int)getpid());
            return;
        }
#endif

        //  Get the next command. If there is none, exit.
        command_t cmd;
        int rc = mailbox.recv (&cmd, 0);
        if (rc != 0 && errno == EINTR)
            continue;
        if (rc != 0 && errno == EAGAIN)
            break;
        errno_assert (rc == 0);

        //  Process the command.
        cmd.destination->process_command (cmd);
    }
}

void zmq::reaper_t::out_event ()
{
    zmq_assert (false);
}

void zmq::reaper_t::timer_event (int)
{
    zmq_assert (false);
}

void zmq::reaper_t::process_stop ()
{
    terminating = true;

    //  If there are no sockets being reaped finish immediately.
    if (!sockets) {
        send_done ();
        poller->rm_fd (mailbox_handle);
        poller->stop ();
    }
}

void zmq::reaper_t::process_reap (socket_base_t *socket_)
{
    //  Add the socket to the poller.
    socket_->start_reaping (poller);

    ++sockets;
}

void zmq::reaper_t::process_reaped ()
{
    --sockets;

    //  If reaped was already asked to terminate and there are no more sockets,
    //  finish immediately.
    if (!sockets && terminating) {
        send_done ();
        poller->rm_fd (mailbox_handle);
        poller->stop ();
    }
}
