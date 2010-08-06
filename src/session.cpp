/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include <new>

#include "session.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"

zmq::session_t::session_t (object_t *parent_, socket_base_t *owner_,
      const options_t &options_) :
    owned_t (parent_, owner_),
    in_pipe (NULL),
    incomplete_in (false),
    active (true),
    out_pipe (NULL),
    engine (NULL),
    options (options_)
{    
    //  It's possible to register the session at this point as it will be
    //  searched for only on reconnect, i.e. no race condition (session found
    //  before it is plugged into it's I/O thread) is possible.
    ordinal = owner->register_session (this);
}

zmq::session_t::session_t (object_t *parent_, socket_base_t *owner_,
      const options_t &options_, const blob_t &peer_identity_) :
    owned_t (parent_, owner_),
    in_pipe (NULL),
    incomplete_in (false),
    active (true),
    out_pipe (NULL),
    engine (NULL),
    ordinal (0),
    peer_identity (peer_identity_),
    options (options_)
{
    if (!peer_identity.empty () && peer_identity [0] != 0) {
        if (!owner->register_session (peer_identity, this)) {

            //  TODO: There's already a session with the specified
            //  identity. We should presumably syslog it and drop the
            //  session.
            zmq_assert (false);
        }
    }
}

zmq::session_t::~session_t ()
{
    zmq_assert (!in_pipe);
    zmq_assert (!out_pipe);
}

bool zmq::session_t::is_terminable ()
{
    return in_pipe->is_terminating ();
}

bool zmq::session_t::read (::zmq_msg_t *msg_)
{
    if (!in_pipe || !active)
        return false;

    if (!in_pipe->read (msg_)) {
        active = false;
        if (in_pipe->is_terminating ())
            finalise ();
        return false;
    }

    incomplete_in = msg_->flags & ZMQ_MSG_MORE;
    return true;
}

bool zmq::session_t::write (::zmq_msg_t *msg_)
{
    if (out_pipe && out_pipe->write (msg_)) {
        zmq_msg_init (msg_);
        return true;
    }

    return false;
}

void zmq::session_t::flush ()
{
    if (out_pipe)
        out_pipe->flush ();
}

void zmq::session_t::detach (owned_t *reconnecter_)
{
    //  Plug in the reconnecter object if any.
    if (reconnecter_) {
        send_plug (reconnecter_);
        send_own (owner, reconnecter_);
    }

    //  Engine is terminating itself. No need to deallocate it from here.
    engine = NULL;

    //  Get rid of half-processed messages in the out pipe. Flush any
    //  unflushed messages upstream.
    if (out_pipe) {
        out_pipe->rollback ();
        out_pipe->flush ();
    }

    //  Remove any half-read message from the in pipe.
    if (in_pipe) {
        while (incomplete_in) {
            zmq_msg_t msg;
            zmq_msg_init (&msg);
            if (!read (&msg)) {
                zmq_assert (!incomplete_in);
                break;
            }
            zmq_msg_close (&msg);
        }
    }
    
    //  Terminate transient session.
    if (!ordinal && (peer_identity.empty () || peer_identity [0] == 0))
        term ();
}

zmq::io_thread_t *zmq::session_t::get_io_thread ()
{
    return choose_io_thread (options.affinity);
}

class zmq::socket_base_t *zmq::session_t::get_owner ()
{
    return owner;
}

uint64_t zmq::session_t::get_ordinal ()
{
    zmq_assert (ordinal);
    return ordinal;
}

void zmq::session_t::attach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    if (inpipe_) {
        zmq_assert (!in_pipe);
        in_pipe = inpipe_;
        active = true;
        in_pipe->set_event_sink (this);
    }

    if (outpipe_) {
        zmq_assert (!out_pipe);
        out_pipe = outpipe_;
        out_pipe->set_event_sink (this);
    }
}

void zmq::session_t::terminated (reader_t *pipe_)
{
    active = false;
    in_pipe = NULL;
}

void zmq::session_t::terminated (writer_t *pipe_)
{
    out_pipe = NULL;
}

void zmq::session_t::activated (reader_t *pipe_)
{
    zmq_assert (in_pipe == pipe_);
    active = true;
    if (engine)
        engine->revive ();
}

void zmq::session_t::activated (writer_t *pipe_)
{
    zmq_assert (out_pipe == pipe_);
    if (engine)
        engine->resume_input ();
}

void zmq::session_t::process_plug ()
{
}

void zmq::session_t::process_unplug ()
{
    //  TODO: There may be a problem here. The called ensures that all the
    //  commands on the fly have been delivered. However, given that the
    //  session is unregistered from the global repository only at this point
    //  there may be some commands being sent to the session right now.

    //  Unregister the session from the socket.
    if (ordinal)
        owner->unregister_session (ordinal);
    else if (!peer_identity.empty () && peer_identity [0] != 0)
        owner->unregister_session (peer_identity);

    //  Ask associated pipes to terminate.
    if (in_pipe)
        in_pipe->terminate ();
    if (out_pipe)
        out_pipe->terminate ();

    if (engine) {
        engine->unplug ();
        delete engine;
        engine = NULL;
    }
}

void zmq::session_t::process_attach (i_engine *engine_,
    const blob_t &peer_identity_)
{
    if (!peer_identity.empty ()) {

        //  If both IDs are temporary, no checking is needed.
        //  TODO: Old ID should be reused in this case...
        if (peer_identity.empty () || peer_identity [0] != 0 ||
            peer_identity_.empty () || peer_identity_ [0] != 0) {

            //  If we already know the peer name do nothing, just check whether
            //  it haven't changed.
            zmq_assert (peer_identity == peer_identity_);
        }
    }
    else if (!peer_identity_.empty ()) {

        //  Store the peer identity.
        peer_identity = peer_identity_;

        //  If the session is not registered with the ordinal, let's register
        //  it using the peer name.
        if (!ordinal) {
            if (!owner->register_session (peer_identity, this)) {

                //  TODO: There's already a session with the specified
                //  identity. We should presumably syslog it and drop the
                //  session.
                zmq_assert (false);
            }
        }
    }

    //  Check whether the required pipes already exist. If not so, we'll
    //  create them and bind them to the socket object.
    reader_t *socket_reader = NULL;
    writer_t *socket_writer = NULL;

    if (options.requires_in && !out_pipe) {
        create_pipe (owner, this, options.hwm, options.swap, &socket_reader,
            &out_pipe);
        out_pipe->set_event_sink (this);
    }

    if (options.requires_out && !in_pipe) {
        create_pipe (this, owner, options.hwm, options.swap, &in_pipe,
            &socket_writer);
        in_pipe->set_event_sink (this);
    }

    if (socket_reader || socket_writer)
        send_bind (owner, socket_reader, socket_writer, peer_identity);

    //  Plug in the engine.
    zmq_assert (!engine);
    zmq_assert (engine_);
    engine = engine_;
    engine->plug (this);
}

