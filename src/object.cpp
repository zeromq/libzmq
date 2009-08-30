/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "object.hpp"
#include "dispatcher.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "io_thread.hpp"
#include "simple_semaphore.hpp"
#include "owned.hpp"
#include "session.hpp"
#include "socket_base.hpp"

zmq::object_t::object_t (dispatcher_t *dispatcher_, int thread_slot_) :
    dispatcher (dispatcher_),
    thread_slot (thread_slot_)
{
}

zmq::object_t::object_t (object_t *parent_) :
    dispatcher (parent_->dispatcher),
    thread_slot (parent_->thread_slot)
{
}

zmq::object_t::~object_t ()
{
}

int zmq::object_t::thread_slot_count ()
{
    return dispatcher->thread_slot_count ();
}

int zmq::object_t::get_thread_slot ()
{
    return thread_slot;
}

void zmq::object_t::process_command (command_t &cmd_)
{
    switch (cmd_.type) {

    case command_t::revive:
        process_revive ();
        break;

    case command_t::stop:
        process_stop ();
        break;

    case command_t::plug:
        process_plug ();
        return;

    case command_t::own:
        process_own (cmd_.args.own.object);
        return;

    case command_t::attach:
        process_attach (cmd_.args.attach.engine);
        return;

    case command_t::bind:
        process_bind (cmd_.args.bind.session,
            cmd_.args.bind.in_pipe, cmd_.args.bind.out_pipe);
        return;

    case command_t::pipe_term:
        process_pipe_term ();
        return;

    case command_t::pipe_term_ack:
        process_pipe_term_ack ();
        return;

    case command_t::term_req:
        process_term_req (cmd_.args.term_req.object);
        return;
    
    case command_t::term:
        process_term ();
        return;

    case command_t::term_ack:
        process_term_ack ();
        return;

    default:
        zmq_assert (false);
    }
}

void zmq::object_t::register_pipe (class pipe_t *pipe_)
{
    dispatcher->register_pipe (pipe_);
}

void zmq::object_t::unregister_pipe (class pipe_t *pipe_)
{
    dispatcher->unregister_pipe (pipe_);
}

zmq::io_thread_t *zmq::object_t::choose_io_thread (uint64_t taskset_)
{
    return dispatcher->choose_io_thread (taskset_);
}

void zmq::object_t::send_stop ()
{
    //  Send command goes always to the current object. To-self pipe is
    //  used exclusively for sending this command.
    command_t cmd;
    cmd.destination = this;
    cmd.type = command_t::stop;
    dispatcher->write (thread_slot, thread_slot, cmd);
}

void zmq::object_t::send_plug (owned_t *destination_)
{
    //  Let the object know that it cannot shut down till it gets this command.
    destination_->inc_seqnum ();

    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::plug;
    send_command (cmd);
}

void zmq::object_t::send_own (socket_base_t *destination_, owned_t *object_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::own;
    cmd.args.own.object = object_;
    send_command (cmd);
}

void zmq::object_t::send_attach (session_t *destination_, i_engine *engine_)
{
    //  The assumption here is that command sequence number of the destination
    //  object was already incremented in find_session function.
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::attach;
    cmd.args.attach.engine = engine_;
    send_command (cmd);
}

void zmq::object_t::send_bind (object_t *destination_, owned_t *session_,
    reader_t *in_pipe_, writer_t *out_pipe_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::bind;
    cmd.args.bind.session = session_;
    cmd.args.bind.in_pipe = in_pipe_;
    cmd.args.bind.out_pipe = out_pipe_;
    send_command (cmd);
}

void zmq::object_t::send_revive (object_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::revive;
    send_command (cmd);
}

void zmq::object_t::send_pipe_term (writer_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::pipe_term;
    send_command (cmd);
}

void zmq::object_t::send_pipe_term_ack (reader_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::pipe_term_ack;
    send_command (cmd);
}

void zmq::object_t::send_term_req (socket_base_t *destination_,
    owned_t *object_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term_req;
    cmd.args.term_req.object = object_;
    send_command (cmd);
}

void zmq::object_t::send_term (owned_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term;
    send_command (cmd);
}

void zmq::object_t::send_term_ack (socket_base_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term_ack;
    send_command (cmd);
}

void zmq::object_t::process_stop ()
{
    zmq_assert (false);
}

void zmq::object_t::process_plug ()
{
    zmq_assert (false);
}

void zmq::object_t::process_own (owned_t *object_)
{
    zmq_assert (false);
}

void zmq::object_t::process_attach (i_engine *engine_)
{
    zmq_assert (false);
}

void zmq::object_t::process_bind (owned_t *session_,
    reader_t *in_pipe_, writer_t *out_pipe_)
{
    zmq_assert (false);
}

void zmq::object_t::process_revive ()
{
    zmq_assert (false);
}

void zmq::object_t::process_pipe_term ()
{
    zmq_assert (false);
}

void zmq::object_t::process_pipe_term_ack ()
{
    zmq_assert (false);
}

void zmq::object_t::process_term_req (owned_t *object_)
{
    zmq_assert (false);
}

void zmq::object_t::process_term ()
{
    zmq_assert (false);
}

void zmq::object_t::process_term_ack ()
{
    zmq_assert (false);
}

void zmq::object_t::send_command (command_t &cmd_)
{
    int destination_thread_slot = cmd_.destination->get_thread_slot ();
    if (destination_thread_slot == thread_slot)
        cmd_.destination->process_command (cmd_);
    else 
        dispatcher->write (thread_slot, destination_thread_slot, cmd_);
}

