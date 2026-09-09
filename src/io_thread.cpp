/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"

#include <new>

#include "macros.hpp"
#include "io_thread.hpp"
#include "err.hpp"
#include "ctx.hpp"
#include "manual_io.hpp"

zmq::io_thread_t::io_thread_t (ctx_t *ctx_, uint32_t tid_) :
    object_t (ctx_, tid_),
    _mailbox_handle (static_cast<poller_t::handle_t> (NULL))
{
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
    _manual_channel = NULL;
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
}

zmq::io_thread_t::~io_thread_t ()
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

void zmq::io_thread_t::start ()
{
#ifdef ZMQ_HAVE_MANUAL_IO
    if (get_ctx ()->is_manual_io ())
        return;
#endif
    char name[16] = "";
    snprintf (name, sizeof (name), "IO/%u",
              get_tid () - zmq::ctx_t::reaper_tid - 1);
    //  Start the underlying I/O thread.
    _poller->start (name);
}

#ifdef ZMQ_HAVE_MANUAL_IO
void zmq::io_thread_t::abort_start ()
{
    if (_mailbox_handle)
        _poller->rm_fd (_mailbox_handle);
}

#endif
void zmq::io_thread_t::stop ()
{
    send_stop ();
}

zmq::mailbox_t *zmq::io_thread_t::get_mailbox ()
{
#ifdef ZMQ_HAVE_MANUAL_IO
    if (_manual_channel)
        return _manual_channel;
#endif
    return &_mailbox;
}

int zmq::io_thread_t::get_load () const
{
    return _poller->get_load ();
}

void zmq::io_thread_t::in_event ()
{
    //  TODO: Do we want to limit number of commands I/O thread can
    //  process in a single go?

    command_t cmd;
    int rc = _mailbox.recv (&cmd, 0);

    while (rc == 0 || errno == EINTR) {
        if (rc == 0)
            cmd.destination->process_command (cmd);
        rc = _mailbox.recv (&cmd, 0);
    }

    errno_assert (rc != 0 && errno == EAGAIN);
}

void zmq::io_thread_t::out_event ()
{
    //  We are never polling for POLLOUT here. This function is never called.
    zmq_assert (false);
}

void zmq::io_thread_t::timer_event (int)
{
    //  No timers here. This function is never called.
    zmq_assert (false);
}

zmq::poller_t *zmq::io_thread_t::get_poller () const
{
    zmq_assert (_poller);
    return _poller;
}

void zmq::io_thread_t::process_stop ()
{
    zmq_assert (_mailbox_handle);
    _poller->rm_fd (_mailbox_handle);
    _poller->stop ();
}
