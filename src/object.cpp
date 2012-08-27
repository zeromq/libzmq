/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include <string.h>
#include <stdarg.h>

#include "object.hpp"
#include "ctx.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "socket_base.hpp"

zmq::object_t::object_t (ctx_t *ctx_, uint32_t tid_) :
    ctx (ctx_),
    tid (tid_)
{
}

zmq::object_t::object_t (object_t *parent_) :
    ctx (parent_->ctx),
    tid (parent_->tid)
{
}

zmq::object_t::~object_t ()
{
}

uint32_t zmq::object_t::get_tid ()
{
    return tid;
}

zmq::ctx_t *zmq::object_t::get_ctx ()
{
    return ctx;
}

void zmq::object_t::process_command (command_t &cmd_)
{
    switch (cmd_.type) {

    case command_t::activate_read:
        process_activate_read ();
        break;

    case command_t::activate_write:
        process_activate_write (cmd_.args.activate_write.msgs_read);
        break;

    case command_t::stop:
        process_stop ();
        break;

    case command_t::plug:
        process_plug ();
        process_seqnum ();
        break;

    case command_t::own:
        process_own (cmd_.args.own.object);
        process_seqnum ();
        break;

    case command_t::attach:
        process_attach (cmd_.args.attach.engine);
        process_seqnum ();
        break;

    case command_t::bind:
        process_bind (cmd_.args.bind.pipe);
        process_seqnum ();
        break;

    case command_t::hiccup:
        process_hiccup (cmd_.args.hiccup.pipe);
        break;

    case command_t::pipe_term:
        process_pipe_term ();
        break;

    case command_t::pipe_term_ack:
        process_pipe_term_ack ();
        break;

    case command_t::term_req:
        process_term_req (cmd_.args.term_req.object);
        break;
    
    case command_t::term:
        process_term (cmd_.args.term.linger);
        break;

    case command_t::term_ack:
        process_term_ack ();
        break;

    case command_t::reap:
        process_reap (cmd_.args.reap.socket);
        break;

    case command_t::reaped:
        process_reaped ();
        break;

    default:
        zmq_assert (false);
    }
}

int zmq::object_t::register_endpoint (const char *addr_, endpoint_t &endpoint_)
{
    return ctx->register_endpoint (addr_, endpoint_);
}

void zmq::object_t::unregister_endpoints (socket_base_t *socket_)
{
    return ctx->unregister_endpoints (socket_);
}

zmq::endpoint_t zmq::object_t::find_endpoint (const char *addr_)
{
    return ctx->find_endpoint (addr_);
}

void zmq::object_t::destroy_socket (socket_base_t *socket_)
{
    ctx->destroy_socket (socket_);
}

zmq::io_thread_t *zmq::object_t::choose_io_thread (uint64_t affinity_)
{
    return ctx->choose_io_thread (affinity_);
}

void zmq::object_t::send_stop ()
{
    //  'stop' command goes always from administrative thread to
    //  the current object. 
    command_t cmd;
    cmd.destination = this;
    cmd.type = command_t::stop;
    ctx->send_command (tid, cmd);
}

void zmq::object_t::send_plug (own_t *destination_, bool inc_seqnum_)
{
    if (inc_seqnum_)
        destination_->inc_seqnum ();

    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::plug;
    send_command (cmd);
}

void zmq::object_t::send_own (own_t *destination_, own_t *object_)
{
    destination_->inc_seqnum ();
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::own;
    cmd.args.own.object = object_;
    send_command (cmd);
}

void zmq::object_t::send_attach (session_base_t *destination_,
    i_engine *engine_, bool inc_seqnum_)
{
    if (inc_seqnum_)
        destination_->inc_seqnum ();

    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::attach;
    cmd.args.attach.engine = engine_;
    send_command (cmd);
}

void zmq::object_t::send_bind (own_t *destination_, pipe_t *pipe_,
    bool inc_seqnum_)
{
    if (inc_seqnum_)
        destination_->inc_seqnum ();

    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::bind;
    cmd.args.bind.pipe = pipe_;
    send_command (cmd);
}

void zmq::object_t::send_activate_read (pipe_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::activate_read;
    send_command (cmd);
}

void zmq::object_t::send_activate_write (pipe_t *destination_,
    uint64_t msgs_read_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::activate_write;
    cmd.args.activate_write.msgs_read = msgs_read_;
    send_command (cmd);
}

void zmq::object_t::send_hiccup (pipe_t *destination_, void *pipe_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::hiccup;
    cmd.args.hiccup.pipe = pipe_;
    send_command (cmd);
}

void zmq::object_t::send_pipe_term (pipe_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::pipe_term;
    send_command (cmd);
}

void zmq::object_t::send_pipe_term_ack (pipe_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::pipe_term_ack;
    send_command (cmd);
}

void zmq::object_t::send_term_req (own_t *destination_,
    own_t *object_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term_req;
    cmd.args.term_req.object = object_;
    send_command (cmd);
}

void zmq::object_t::send_term (own_t *destination_, int linger_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term;
    cmd.args.term.linger = linger_;
    send_command (cmd);
}

void zmq::object_t::send_term_ack (own_t *destination_)
{
    command_t cmd;
    cmd.destination = destination_;
    cmd.type = command_t::term_ack;
    send_command (cmd);
}

void zmq::object_t::send_reap (class socket_base_t *socket_)
{
    command_t cmd;
    cmd.destination = ctx->get_reaper ();
    cmd.type = command_t::reap;
    cmd.args.reap.socket = socket_;
    send_command (cmd);
}

void zmq::object_t::send_reaped ()
{
    command_t cmd;
    cmd.destination = ctx->get_reaper ();
    cmd.type = command_t::reaped;
    send_command (cmd);
}

void zmq::object_t::send_done ()
{
    command_t cmd;
    cmd.destination = NULL;
    cmd.type = command_t::done;
    ctx->send_command (ctx_t::term_tid, cmd);
}

void zmq::object_t::process_stop ()
{
    zmq_assert (false);
}

void zmq::object_t::process_plug ()
{
    zmq_assert (false);
}

void zmq::object_t::process_own (own_t *)
{
    zmq_assert (false);
}

void zmq::object_t::process_attach (i_engine *)
{
    zmq_assert (false);
}

void zmq::object_t::process_bind (pipe_t *)
{
    zmq_assert (false);
}

void zmq::object_t::process_activate_read ()
{
    zmq_assert (false);
}

void zmq::object_t::process_activate_write (uint64_t)
{
    zmq_assert (false);
}

void zmq::object_t::process_hiccup (void *)
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

void zmq::object_t::process_term_req (own_t *)
{
    zmq_assert (false);
}

void zmq::object_t::process_term (int)
{
    zmq_assert (false);
}

void zmq::object_t::process_term_ack ()
{
    zmq_assert (false);
}

void zmq::object_t::process_reap (class socket_base_t *)
{
    zmq_assert (false);
}

void zmq::object_t::process_reaped ()
{
    zmq_assert (false);
}

void zmq::object_t::process_seqnum ()
{
    zmq_assert (false);
}

void zmq::object_t::send_command (command_t &cmd_)
{
    ctx->send_command (cmd_.destination->get_tid (), cmd_);
}

