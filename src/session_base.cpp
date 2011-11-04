/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
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

#include "session_base.hpp"
#include "socket_base.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "likely.hpp"
#include "tcp_connecter.hpp"
#include "ipc_connecter.hpp"
#include "pgm_sender.hpp"
#include "pgm_receiver.hpp"

#include "req.hpp"
#include "xreq.hpp"
#include "rep.hpp"
#include "xrep.hpp"
#include "pub.hpp"
#include "xpub.hpp"
#include "sub.hpp"
#include "xsub.hpp"
#include "push.hpp"
#include "pull.hpp"
#include "pair.hpp"

zmq::session_base_t *zmq::session_base_t::create (class io_thread_t *io_thread_,
    bool connect_, class socket_base_t *socket_, const options_t &options_,
    const char *protocol_, const char *address_)
{
    session_base_t *s = NULL;
    switch (options_.type) {
    case ZMQ_REQ:
        s = new (std::nothrow) req_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_XREQ:
        s = new (std::nothrow) xreq_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
    case ZMQ_REP:
        s = new (std::nothrow) rep_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_XREP:
        s = new (std::nothrow) xrep_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_PUB:
        s = new (std::nothrow) pub_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_XPUB:
        s = new (std::nothrow) xpub_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_SUB:
        s = new (std::nothrow) sub_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_XSUB:
        s = new (std::nothrow) xsub_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_PUSH:
        s = new (std::nothrow) push_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_PULL:
        s = new (std::nothrow) pull_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    case ZMQ_PAIR:
        s = new (std::nothrow) pair_session_t (io_thread_, connect_,
            socket_, options_, protocol_, address_);
        break;
    default:
        errno = EINVAL;
        return NULL;
    }
    alloc_assert (s);
    return s;
}

zmq::session_base_t::session_base_t (class io_thread_t *io_thread_,
      bool connect_, class socket_base_t *socket_, const options_t &options_,
      const char *protocol_, const char *address_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    connect (connect_),
    pipe (NULL),
    incomplete_in (false),
    pending (false),
    engine (NULL),
    socket (socket_),
    io_thread (io_thread_),
    has_linger_timer (false),
    send_identity (options_.send_identity),
    recv_identity (options_.recv_identity)
{
    if (protocol_)
        protocol = protocol_;
    if (address_)
        address = address_;
}

zmq::session_base_t::~session_base_t ()
{
    zmq_assert (!pipe);

    //  If there's still a pending linger timer, remove it.
    if (has_linger_timer) {
        cancel_timer (linger_timer_id);
        has_linger_timer = false;
    }

    //  Close the engine.
    if (engine)
        engine->terminate ();
}

void zmq::session_base_t::attach_pipe (pipe_t *pipe_)
{
    zmq_assert (!is_terminating ());
    zmq_assert (!pipe);
    zmq_assert (pipe_);
    pipe = pipe_;
    pipe->set_event_sink (this);
}

int zmq::session_base_t::read (msg_t *msg_)
{
    //  First message to send is identity (if required).
    if (send_identity) {
        zmq_assert (!(msg_->flags () & msg_t::more));
        msg_->init_size (options.identity_size);
        memcpy (msg_->data (), options.identity, options.identity_size);
        send_identity = false;
        incomplete_in = false;
        return 0;
    }

    if (!pipe || !pipe->read (msg_)) {
        errno = EAGAIN;
        return -1;
    }
    incomplete_in = msg_->flags () & msg_t::more ? true : false;

    return 0;
}

int zmq::session_base_t::write (msg_t *msg_)
{
    //  First message to receive is identity (if required).
    if (recv_identity) {
        msg_->set_flags (msg_t::identity);
        recv_identity = false;
    }

    if (pipe && pipe->write (msg_)) {
        int rc = msg_->init ();
        errno_assert (rc == 0);
        return 0;
    }

    errno = EAGAIN;
    return -1;
}

void zmq::session_base_t::flush ()
{
    if (pipe)
        pipe->flush ();
}

void zmq::session_base_t::clean_pipes ()
{
    if (pipe) {

        //  Get rid of half-processed messages in the out pipe. Flush any
        //  unflushed messages upstream.
        pipe->rollback ();
        pipe->flush ();

        //  Remove any half-read message from the in pipe.
        while (incomplete_in) {
            msg_t msg;
            int rc = msg.init ();
            errno_assert (rc == 0);
            if (!read (&msg)) {
                zmq_assert (!incomplete_in);
                break;
            }
            rc = msg.close ();
            errno_assert (rc == 0);
        }
    }
}

void zmq::session_base_t::terminated (pipe_t *pipe_)
{
    //  Drop the reference to the deallocated pipe.
    zmq_assert (pipe == pipe_);
    pipe = NULL;

    //  If we are waiting for pending messages to be sent, at this point
    //  we are sure that there will be no more messages and we can proceed
    //  with termination safely.
    if (pending)
        proceed_with_term ();
}

void zmq::session_base_t::read_activated (pipe_t *pipe_)
{
    zmq_assert (pipe == pipe_);

    if (likely (engine != NULL))
        engine->activate_out ();
    else
        pipe->check_read ();
}

void zmq::session_base_t::write_activated (pipe_t *pipe_)
{
    zmq_assert (pipe == pipe_);

    if (engine)
        engine->activate_in ();
}

void zmq::session_base_t::hiccuped (pipe_t *pipe_)
{
    //  Hiccups are always sent from session to socket, not the other
    //  way round.
    zmq_assert (false);
}

void zmq::session_base_t::process_plug ()
{
    if (connect)
        start_connecting (false);
}

void zmq::session_base_t::process_attach (i_engine *engine_)
{
    //  If some other object (e.g. init) notifies us that the connection failed
    //  without creating an engine we need to start the reconnection process.
    if (!engine_) {
        zmq_assert (!engine);
        detached ();
        return;
    }

    //  Create the pipe if it does not exist yet.
    if (!pipe && !is_terminating ()) {
        object_t *parents [2] = {this, socket};
        pipe_t *pipes [2] = {NULL, NULL};
        int hwms [2] = {options.rcvhwm, options.sndhwm};
        bool delays [2] = {options.delay_on_close, options.delay_on_disconnect};
        int rc = pipepair (parents, pipes, hwms, delays);
        errno_assert (rc == 0);

        //  Plug the local end of the pipe.
        pipes [0]->set_event_sink (this);

        //  Remember the local end of the pipe.
        zmq_assert (!pipe);
        pipe = pipes [0];

        //  Ask socket to plug into the remote end of the pipe.
        send_bind (socket, pipes [1]);
    }

    //  Plug in the engine.
    zmq_assert (!engine);
    engine = engine_;
    engine->plug (io_thread, this);
}

void zmq::session_base_t::detach ()
{
    //  Engine is dead. Let's forget about it.
    engine = NULL;

    //  Remove any half-done messages from the pipes.
    clean_pipes ();

    //  Send the event to the derived class.
    detached ();

    //  Just in case there's only a delimiter in the pipe.
    if (pipe)
        pipe->check_read ();
}

void zmq::session_base_t::process_term (int linger_)
{
    zmq_assert (!pending);

    //  If the termination of the pipe happens before the term command is
    //  delivered there's nothing much to do. We can proceed with the
    //  stadard termination immediately.
    if (!pipe) {
        proceed_with_term ();
        return;
    }

    pending = true;

    //  If there's finite linger value, delay the termination.
    //  If linger is infinite (negative) we don't even have to set
    //  the timer.
    if (linger_ > 0) {
        zmq_assert (!has_linger_timer);
        add_timer (linger_, linger_timer_id);
        has_linger_timer = true;
    }

    //  Start pipe termination process. Delay the termination till all messages
    //  are processed in case the linger time is non-zero.
    pipe->terminate (linger_ != 0);

    //  TODO: Should this go into pipe_t::terminate ?
    //  In case there's no engine and there's only delimiter in the
    //  pipe it wouldn't be ever read. Thus we check for it explicitly.
    pipe->check_read ();
}

void zmq::session_base_t::proceed_with_term ()
{
    //  The pending phase have just ended.
    pending = false;

    //  Continue with standard termination.
    own_t::process_term (0);
}

void zmq::session_base_t::timer_event (int id_)
{
    //  Linger period expired. We can proceed with termination even though
    //  there are still pending messages to be sent.
    zmq_assert (id_ == linger_timer_id);
    has_linger_timer = false;

    //  Ask pipe to terminate even though there may be pending messages in it.
    zmq_assert (pipe);
    pipe->terminate (false);
}

void zmq::session_base_t::detached ()
{
    //  Transient session self-destructs after peer disconnects.
    if (!connect) {
        terminate ();
        return;
    }

    //  Reconnect.
    start_connecting (true);

    //  For subscriber sockets we hiccup the inbound pipe, which will cause
    //  the socket object to resend all the subscriptions.
    if (pipe && (options.type == ZMQ_SUB || options.type == ZMQ_XSUB))
        pipe->hiccup ();  
}

void zmq::session_base_t::start_connecting (bool wait_)
{
    zmq_assert (connect);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create the connecter object.

    if (protocol == "tcp") {
        tcp_connecter_t *connecter = new (std::nothrow) tcp_connecter_t (
            io_thread, this, options, address.c_str (), wait_);
        alloc_assert (connecter);
        launch_child (connecter);
        return;
    }

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    if (protocol == "ipc") {
        ipc_connecter_t *connecter = new (std::nothrow) ipc_connecter_t (
            io_thread, this, options, address.c_str (), wait_);
        alloc_assert (connecter);
        launch_child (connecter);
        return;
    }
#endif

#if defined ZMQ_HAVE_OPENPGM

    //  Both PGM and EPGM transports are using the same infrastructure.
    if (protocol == "pgm" || protocol == "epgm") {

        //  For EPGM transport with UDP encapsulation of PGM is used.
        bool udp_encapsulation = (protocol == "epgm");

        //  At this point we'll create message pipes to the session straight
        //  away. There's no point in delaying it as no concept of 'connect'
        //  exists with PGM anyway.
        if (options.type == ZMQ_PUB || options.type == ZMQ_XPUB) {

            //  PGM sender.
            pgm_sender_t *pgm_sender =  new (std::nothrow) pgm_sender_t (
                io_thread, options);
            alloc_assert (pgm_sender);

            int rc = pgm_sender->init (udp_encapsulation, address.c_str ());
            zmq_assert (rc == 0);

            send_attach (this, pgm_sender);
        }
        else if (options.type == ZMQ_SUB || options.type == ZMQ_XSUB) {

            //  PGM receiver.
            pgm_receiver_t *pgm_receiver =  new (std::nothrow) pgm_receiver_t (
                io_thread, options);
            alloc_assert (pgm_receiver);

            int rc = pgm_receiver->init (udp_encapsulation, address.c_str ());
            zmq_assert (rc == 0);

            send_attach (this, pgm_receiver);
        }
        else
            zmq_assert (false);

        return;
    }
#endif

    zmq_assert (false);
}

