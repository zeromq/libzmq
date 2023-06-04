/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "io_object.hpp"
#include "io_thread.hpp"
#include "err.hpp"

zmq::io_object_t::io_object_t (io_thread_t *io_thread_) : _poller (NULL)
{
    if (io_thread_)
        plug (io_thread_);
}

zmq::io_object_t::~io_object_t ()
{
}

void zmq::io_object_t::plug (io_thread_t *io_thread_)
{
    zmq_assert (io_thread_);
    zmq_assert (!_poller);

    //  Retrieve the poller from the thread we are running in.
    _poller = io_thread_->get_poller ();
}

void zmq::io_object_t::unplug ()
{
    zmq_assert (_poller);

    //  Forget about old poller in preparation to be migrated
    //  to a different I/O thread.
    _poller = NULL;
}

zmq::io_object_t::handle_t zmq::io_object_t::add_fd (fd_t fd_)
{
    return _poller->add_fd (fd_, this);
}

void zmq::io_object_t::rm_fd (handle_t handle_)
{
    _poller->rm_fd (handle_);
}

void zmq::io_object_t::set_pollin (handle_t handle_)
{
    _poller->set_pollin (handle_);
}

void zmq::io_object_t::reset_pollin (handle_t handle_)
{
    _poller->reset_pollin (handle_);
}

void zmq::io_object_t::set_pollout (handle_t handle_)
{
    _poller->set_pollout (handle_);
}

void zmq::io_object_t::reset_pollout (handle_t handle_)
{
    _poller->reset_pollout (handle_);
}

void zmq::io_object_t::add_timer (int timeout_, int id_)
{
    _poller->add_timer (timeout_, this, id_);
}

void zmq::io_object_t::cancel_timer (int id_)
{
    _poller->cancel_timer (this, id_);
}

void zmq::io_object_t::in_event ()
{
    zmq_assert (false);
}

void zmq::io_object_t::out_event ()
{
    zmq_assert (false);
}

void zmq::io_object_t::timer_event (int)
{
    zmq_assert (false);
}
