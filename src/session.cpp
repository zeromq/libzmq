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

#include "../include/zmq.h"

#include "session.hpp"
#include "i_engine.hpp"
#include "i_thread.hpp"
#include "i_mux.hpp"
#include "i_demux.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "pipe_reader.hpp"
#include "pipe_writer.hpp"
#include "simple_semaphore.hpp"

zmq::session_t::session_t (object_t *parent_, i_thread *thread_,
      i_mux *mux_, i_demux *demux_,
      bool terminate_on_disconnect_, bool terminate_on_no_pipes_) :
    safe_object_t (parent_),
    mux (mux_),
    demux (demux_),
    thread (thread_),
    engine (NULL),
    terminate_on_disconnect (terminate_on_disconnect_),
    terminate_on_no_pipes (false),
    terminate_on_no_pipes_delayed (terminate_on_no_pipes_),
    index (-1)
{
    //  At least one way to terminate the session should be allowed. Otherwise
    //  the session can be orphaned forever.
    zmq_assert (terminate_on_disconnect || terminate_on_no_pipes_delayed);

    //  Give the mux and the demux callback pointer to ourselves.
    if (mux)
        mux->set_session (this);
    if (demux)
        demux->set_session (this);
}

void zmq::session_t::shutdown ()
{
    //  Session may live even without an associated engine, thus we have
    //  to check if for NULL value.
    if (engine)
        engine->shutdown ();

    //  Propagate the shutdown signal to both inbound and outbound pipes.
    if (mux)
        mux->shutdown ();
    if (demux)
        demux->shutdown ();

    delete this;
}

void zmq::session_t::disconnected ()
{
    //  It's engine who calls this function so there's no need to deallocate
    //  the engine. Just drop the reference.
    engine = NULL;

    //  Some sessions won't shut down because of disconnect. New engine will
    //  attached to the session later on.
    if (!terminate_on_disconnect)
        return;

    terminate ();
}

void zmq::session_t::bind (object_t *peer_, bool in_, bool out_)
{
    //  Create the out pipe (if required).
    pipe_reader_t *pipe_reader = NULL;
    if (out_) {
        pipe_writer_t *pipe_writer;
        create_pipe (peer_, this, 0, 0, &pipe_reader, &pipe_writer);
        demux->attach_pipe (pipe_writer);

        //  There's at least one pipe attached. We can deallocate the object
        //  when there are no pipes (if required).
        terminate_on_no_pipes = terminate_on_no_pipes_delayed;
    }

    //  Ask peer to attach to the out pipe (if one exists). If required, ask
    //  it to create a pipe in opposite direction. It's assumed that peer's
    //  seqnum was already incremented, so we don't need to care whether it's
    //  alive at the moment.
    if (in_)
        inc_seqnum ();
    send_bind (peer_, pipe_reader, in_ ? this : NULL);
}

void zmq::session_t::revive ()
{
    if (engine)
        engine->revive ();
}

void zmq::session_t::terminate ()
{
    //  Terminate is always called by engine, thus it'll terminate itself,
    //  we just have to drop the pointer.
    engine = NULL;

    //  Propagate the terminate signal to both inbound and outbound pipes.
    if (mux) {
        mux->terminate ();
        mux = NULL;
    }
    if (demux) {
        demux->terminate ();
        demux = NULL;
    }

    //  Session cannot be deallocated at this point. There can still be
    //  pending commands to process. Unregister session from global
    //  repository thus ensuring that no new commands will be sent.
    unregister_inproc_endpoints (this);

    //  Move to terminating state.
    safe_object_t::terminate ();
}

zmq::session_t::~session_t ()
{
    //  When session is actually deallocated it unregisters from its thread.
    //  Unregistration cannot be done earlier as it would result in memory
    //  leak if global shutdown happens in the middle of session termination.
    thread->detach_session (this);
}

void zmq::session_t::set_engine (i_engine *engine_)
{
    zmq_assert (!engine || !engine_);
    engine = engine_;
}

void zmq::session_t::set_index (int index_)
{
    index = index_;
}

int zmq::session_t::get_index ()
{
    return index;
}

bool zmq::session_t::write (zmq_msg *msg_)
{
    return demux->send (msg_);
}

void zmq::session_t::flush ()
{
    demux->flush ();
}

bool zmq::session_t::read (zmq_msg *msg_)
{
    bool retrieved = mux->recv (msg_);
    if (terminate_on_no_pipes && mux->empty () && demux->empty ()) {
        zmq_assert (engine);
        engine->schedule_terminate ();
        terminate ();
    }
    return retrieved;
}

void zmq::session_t::process_bind (pipe_reader_t *reader_, session_t *peer_)
{
    if (is_terminating ()) {

        //  If session is already in termination phase, we'll ask newly arrived
        //  pipe reader & writer to terminate straight away.
        if (reader_)
            reader_->terminate ();

        //  Peer session has already incremented its seqnum. We have to send
        //  a dummy command to avoid a memory leak.
        if (peer_)
            send_bind (peer_, NULL, NULL);

        return;
    }

    //  If inbound pipe is provided, bind it to the mux.
    if (reader_) {
        mux->attach_pipe (reader_);

        //  There's at least one pipe attached. We can deallocate the object
        //  when there are no pipes (if required).
        terminate_on_no_pipes = terminate_on_no_pipes_delayed;
    }

    //  If peer wants to get messages from ourselves, we'll bind to it.
    if (peer_) {
        pipe_reader_t *pipe_reader;
        pipe_writer_t *pipe_writer;
        create_pipe (peer_, this, 0, 0, &pipe_reader, &pipe_writer);
        demux->attach_pipe (pipe_writer);
        send_bind (peer_, pipe_reader, NULL);

        //  There's at least one pipe attached. We can deallocate the object
        //  when there are no pipes (if required).
        terminate_on_no_pipes = terminate_on_no_pipes_delayed;
    }
}

void zmq::session_t::process_reg (simple_semaphore_t *smph_)
{
    zmq_assert (!is_terminating ());

    //  Add the session to the list of sessions associated with this I/O thread.
    //  This way the session will be deallocated on the terminal shutdown.
    thread->attach_session (this);

    //  Release calling thead (if required).
    if (smph_)
        smph_->post ();
}

void zmq::session_t::process_reg_and_bind (session_t *peer_,
    bool flow_in_, bool flow_out_)
{
    zmq_assert (!is_terminating ());

    //  Add the session to the list of sessions associated with this I/O thread.
    //  This way the session will be deallocated on the terminal shutdown.
    thread->attach_session (this);

    //  Bind to the peer. Note that caller have already incremented command
    //  sequence number of the peer so we are sure it still exists.
    pipe_reader_t *pipe_reader = NULL;
    if (flow_out_) {
        pipe_writer_t *pipe_writer;
        create_pipe (peer_, this, 0, 0, &pipe_reader, &pipe_writer);
        demux->attach_pipe (pipe_writer);

        //  There's at least one pipe attached. We can deallocate the object
        //  when there are no pipes (if required).
        terminate_on_no_pipes = terminate_on_no_pipes_delayed;
    }
    send_bind (peer_, pipe_reader, flow_in_ ? this : NULL);
}

void zmq::session_t::process_engine (i_engine *engine_)
{
    if (is_terminating ()) {

        //  Kill the engine. It won't be needed anymore.
        engine_->terminate ();
        return;
    }

    engine_->attach (thread->get_poller (), this);
}
