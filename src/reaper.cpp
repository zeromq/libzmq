/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "macros.hpp"
#include <new>
#include "reaper.hpp"
#include "socket_base.hpp"
#include "err.hpp"
#include "manual_io.hpp"

zmq::reaper_t::reaper_t (class ctx_t *ctx_, uint32_t tid_) :
    object_t (ctx_, tid_),
    _mailbox_handle (static_cast<poller_t::handle_t> (NULL)),
    _poller (NULL),
    _sockets (0),
    _terminating (false)
{
#ifdef ZMQ_HAVE_MANUAL_IO
    _manual_receiver = NULL;
    _manual_channel = NULL;
#endif
    if (!_mailbox.valid ())
        return;

#ifdef ZMQ_HAVE_MANUAL_IO
    if (ctx_->get_manual_io ())
        _poller = ctx_->get_manual_io ()->poller ();
    else
#endif
        _poller = new (std::nothrow) poller_t (*ctx_);
    alloc_assert (_poller);

    i_poll_events *receiver = this;
#ifdef ZMQ_HAVE_MANUAL_IO
    _manual_receiver = NULL;
    if (ctx_->get_manual_io ()) {
        _mailbox.set_manual_cleanup ();
        _manual_channel = new (std::nothrow) manual_mailbox_channel_t ();
        alloc_assert (_manual_channel);
        _manual_receiver = new (std::nothrow)
          manual_mailbox_t (*ctx_->get_manual_io (), *_manual_channel);
        alloc_assert (_manual_receiver);
        receiver = _manual_receiver;
    }
#endif

    if (get_mailbox ()->get_fd () != retired_fd) {
        _mailbox_handle = _poller->add_fd (get_mailbox ()->get_fd (), receiver);
        _poller->set_pollin (_mailbox_handle);
    }

#ifdef HAVE_FORK
    _pid = getpid ();
#endif
}

zmq::reaper_t::~reaper_t ()
{
#ifdef ZMQ_HAVE_MANUAL_IO
    if (get_ctx ()->is_manual_io ()) {
        LIBZMQ_DELETE (_manual_receiver);
        LIBZMQ_DELETE (_manual_channel);
        return;
    }
#endif
    LIBZMQ_DELETE (_poller);
}

zmq::mailbox_t *zmq::reaper_t::get_mailbox ()
{
#ifdef ZMQ_HAVE_MANUAL_IO
    if (_manual_channel)
        return _manual_channel;
#endif
    return &_mailbox;
}

void zmq::reaper_t::start ()
{
#ifdef ZMQ_HAVE_MANUAL_IO
    if (get_ctx ()->is_manual_io ())
        return;
#endif
    zmq_assert (_mailbox.valid ());

    //  Start the thread.
    _poller->start ("Reaper");
}

#ifdef ZMQ_HAVE_MANUAL_IO
void zmq::reaper_t::abort_start ()
{
    if (_mailbox_handle)
        _poller->rm_fd (_mailbox_handle);
}

#endif
void zmq::reaper_t::stop ()
{
    if (get_mailbox ()->valid ()) {
        send_stop ();
    }
}

void zmq::reaper_t::in_event ()
{
    while (true) {
#ifdef HAVE_FORK
        if (unlikely (_pid != getpid ())) {
            //printf("zmq::reaper_t::in_event return in child process %d\n", (int)getpid());
            return;
        }
#endif

        //  Get the next command. If there is none, exit.
        command_t cmd;
        const int rc = _mailbox.recv (&cmd, 0);
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
    _terminating = true;

    //  If there are no sockets being reaped finish immediately.
    if (!_sockets) {
        send_done ();
        _poller->rm_fd (_mailbox_handle);
        _poller->stop ();
    }
}

void zmq::reaper_t::process_reap (socket_base_t *socket_)
{
    //  Add the socket to the poller.
    socket_->start_reaping (_poller);

    ++_sockets;
}

void zmq::reaper_t::process_reaped ()
{
    --_sockets;

    //  If reaped was already asked to terminate and there are no more sockets,
    //  finish immediately.
    if (!_sockets && _terminating) {
        send_done ();
        _poller->rm_fd (_mailbox_handle);
        _poller->stop ();
    }
}
