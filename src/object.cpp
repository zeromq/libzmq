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
#include "context.hpp"
#include "err.hpp"
#include "io_thread.hpp"
#include "simple_semaphore.hpp"

zmq::object_t::object_t (context_t *context_, int thread_slot_) :
    context (context_),
    thread_slot (thread_slot_)
{
}

zmq::object_t::object_t (object_t *parent_) :
    context (parent_->context),
    thread_slot (parent_->thread_slot)
{
}

zmq::object_t::~object_t ()
{
}

int zmq::object_t::thread_slot_count ()
{
    return context->thread_slot_count ();
}

int zmq::object_t::get_thread_slot ()
{
    return thread_slot;
}

void zmq::object_t::process_command (command_t &cmd_)
{
    switch (cmd_.type) {

    case command_t::head:
        process_head (cmd_.args.head.bytes);
        break;

    case command_t::tail:
        process_tail (cmd_.args.tail.bytes);
        break;

    case command_t::engine:
        process_engine (cmd_.args.engine.engine);
        break;

    case command_t::bind:
        process_bind (cmd_.args.bind.reader, cmd_.args.bind.peer);
        break;

    case command_t::reg:
        process_reg (cmd_.args.reg.smph);
        break;

    case command_t::reg_and_bind:
        process_reg_and_bind (cmd_.args.reg_and_bind.peer,
            cmd_.args.reg_and_bind.flow_in, cmd_.args.reg_and_bind.flow_out);
        break;

    case command_t::unreg:
        process_unreg (cmd_.args.unreg.smph);
        break;

    case command_t::terminate:
        process_terminate ();
        break;

    case command_t::terminate_ack:
        process_terminate_ack ();
        break;

    case command_t::stop:
        process_stop ();
        return;

    default:
        zmq_assert (false);
    }
}

zmq::io_thread_t *zmq::object_t::choose_io_thread (uint64_t taskset_)
{
    return context->choose_io_thread (taskset_);
}

void zmq::object_t::send_stop ()
{
    //  Send command goes always to the current object. To-self pipe is
    //  used exclusively for sending this command.
    command_t cmd;
    cmd.destination = this;
    cmd.type = command_t::stop;
    context->write (thread_slot, thread_slot, cmd);
}

void zmq::object_t::send_bind (object_t *destination_, pipe_reader_t *reader_,
    session_t *peer_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::bind;
    cmd.args.bind.reader = reader_;
    cmd.args.bind.peer = peer_;
    send_command (cmd);
}

void zmq::object_t::send_head (object_t *destination_, uint64_t bytes_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::head;
    cmd.args.head.bytes = bytes_;
    send_command (cmd);
}

void zmq::object_t::send_tail (object_t *destination_, uint64_t bytes_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::tail;
    cmd.args.tail.bytes = bytes_;
    send_command (cmd);
}

void zmq::object_t::send_reg (object_t *destination_, simple_semaphore_t *smph_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::reg;
    cmd.args.reg.smph = smph_;
    send_command (cmd);
}

void zmq::object_t::send_reg_and_bind (object_t *destination_,
    session_t *peer_, bool flow_in_, bool flow_out_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::reg_and_bind;
    cmd.args.reg_and_bind.peer = peer_;
    cmd.args.reg_and_bind.flow_in = flow_in_;
    cmd.args.reg_and_bind.flow_out = flow_out_;
    send_command (cmd);
}

void zmq::object_t::send_unreg (object_t *destination_,
    simple_semaphore_t *smph_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::unreg;
    cmd.args.unreg.smph = smph_;
    send_command (cmd);
}

void zmq::object_t::send_engine (object_t *destination_, i_engine *engine_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::engine;
    cmd.args.engine.engine = engine_;
    send_command (cmd);
}

void zmq::object_t::send_terminate (object_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::terminate;
    send_command (cmd);
}

void zmq::object_t::send_terminate_ack (object_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::terminate_ack;
    send_command (cmd);
}

void zmq::object_t::process_stop ()
{
    zmq_assert (false);
}

void zmq::object_t::process_bind (pipe_reader_t *reader_, session_t *peer_)
{
    zmq_assert (false);
}

void zmq::object_t::process_head (uint64_t bytes_)
{
    zmq_assert (false);
}

void zmq::object_t::process_tail (uint64_t bytes_)
{
    zmq_assert (false);
}

void zmq::object_t::process_reg (simple_semaphore_t *smph_)
{
    zmq_assert (false);
}

void zmq::object_t::process_reg_and_bind (session_t *session_,
    bool flow_in_, bool flow_out_)
{
    zmq_assert (false);
}

void zmq::object_t::process_unreg (simple_semaphore_t *smph_)
{
    zmq_assert (false);
}

void zmq::object_t::process_engine (i_engine *engine_)
{
    zmq_assert (false);
}

void zmq::object_t::process_terminate ()
{
    zmq_assert (false);
}

void zmq::object_t::process_terminate_ack ()
{
    zmq_assert (false);
}

void zmq::object_t::send_command (command_t &cmd_)
{
    int destination_thread_slot = cmd_.destination->get_thread_slot ();
    if (destination_thread_slot == thread_slot)
        cmd_.destination->process_command (cmd_);
    else 
        context->write (thread_slot, destination_thread_slot, cmd_);
}

