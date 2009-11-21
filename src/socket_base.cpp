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

#include <string>
#include <algorithm>

#include "../bindings/c/zmq.h"

#include "socket_base.hpp"
#include "app_thread.hpp"
#include "dispatcher.hpp"
#include "zmq_listener.hpp"
#include "zmq_connecter.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "config.hpp"
#include "owned.hpp"
#include "uuid.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "platform.hpp"
#include "pgm_sender.hpp"
#include "pgm_receiver.hpp"

zmq::socket_base_t::socket_base_t (app_thread_t *parent_) :
    object_t (parent_),
    pending_term_acks (0),
    ticks (0),
    app_thread (parent_),
    shutting_down (false),
    sent_seqnum (0),
    processed_seqnum (0)
{
}

zmq::socket_base_t::~socket_base_t ()
{
}

int zmq::socket_base_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    //  First, check whether specific socket type overloads the option.
    int rc = xsetsockopt (option_, optval_, optvallen_);
    if (rc == 0 || errno != EINVAL)
        return rc;

    //  If the socket type doesn't support the option, pass it to
    //  the generic option parser.
    return options.setsockopt (option_, optval_, optvallen_);
}

int zmq::socket_base_t::bind (const char *addr_)
{
    //  Parse addr_ string.
    std::string addr_type;
    std::string addr_args;

    std::string addr (addr_);
    std::string::size_type pos = addr.find ("://");

    if (pos == std::string::npos) {
        errno = EINVAL;
        return -1;
    }

    addr_type = addr.substr (0, pos);
    addr_args = addr.substr (pos + 3);

    if (addr_type == "inproc")
        return register_endpoint (addr_args.c_str (), this);

    if (addr_type == "tcp") {
        zmq_listener_t *listener = new zmq_listener_t (
            choose_io_thread (options.affinity), this, options);
        int rc = listener->set_address (addr_args.c_str ());
        if (rc != 0)
            return -1;

        send_plug (listener);
        send_own (this, listener);
        return 0;
    }

#if defined ZMQ_HAVE_OPENPGM
    if (addr_type == "pgm" || addr_type == "udp") {
        //  In the case of PGM bind behaves the same like connect.
        return connect (addr_); 
    }
#endif

    //  Unknown protocol.
    errno = EPROTONOSUPPORT;
    return -1;
}

int zmq::socket_base_t::connect (const char *addr_)
{
    //  Generate a unique name for the session.
    std::string session_name ("#");
    session_name += uuid_t ().to_string ();

    //  Parse addr_ string.
    std::string addr_type;
    std::string addr_args;

    std::string addr (addr_);
    std::string::size_type pos = addr.find ("://");

    if (pos == std::string::npos) {
        errno = EINVAL;
        return -1;
    }

    addr_type = addr.substr (0, pos);
    addr_args = addr.substr (pos + 3);

    if (addr_type == "inproc") {

        //  Find the peer socket.
        socket_base_t *peer = find_endpoint (addr_args.c_str ());
        if (!peer)
            return -1;

        pipe_t *in_pipe = NULL;
        pipe_t *out_pipe = NULL;

        //  Create inbound pipe, if required.
        if (options.requires_in) {
            in_pipe = new pipe_t (this, peer, options.hwm, options.lwm);
            zmq_assert (in_pipe);
        }

        //  Create outbound pipe, if required.
        if (options.requires_out) {
            out_pipe = new pipe_t (peer, this, options.hwm, options.lwm);
            zmq_assert (out_pipe);
        }

        //  Attach the pipes to this socket object.
        attach_pipes (in_pipe ? &in_pipe->reader : NULL,
            out_pipe ? &out_pipe->writer : NULL);

        //  Attach the pipes to the peer socket. Note that peer's seqnum
        //  was incremented in find_endpoint function. When this command
        //  is delivered, peer will consider the seqnum to be processed.
        //  TODO: Seems that 'session' parameter is unused...
        send_bind (peer, NULL, out_pipe ? &out_pipe->reader : NULL,
            in_pipe ? &in_pipe->writer : NULL);

        return 0;
    }

    //  Create the session.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    session_t *session = new session_t (io_thread, this, session_name.c_str (),
        options, true);
    zmq_assert (session);

    pipe_t *in_pipe = NULL;
    pipe_t *out_pipe = NULL;

    //  Create inbound pipe, if required.
    if (options.requires_in) {
        in_pipe = new pipe_t (this, session, options.hwm, options.lwm);
        zmq_assert (in_pipe);

    }

    //  Create outbound pipe, if required.
    if (options.requires_out) {
        out_pipe = new pipe_t (session, this, options.hwm, options.lwm);
        zmq_assert (out_pipe);
    }

    //  Attach the pipes to the socket object.
    attach_pipes (in_pipe ? &in_pipe->reader : NULL,
        out_pipe ? &out_pipe->writer : NULL);

    //  Attach the pipes to the session object.
    session->attach_pipes (out_pipe ? &out_pipe->reader : NULL,
        in_pipe ? &in_pipe->writer : NULL);

    //  Activate the session.
    send_plug (session);
    send_own (this, session);

    if (addr_type == "tcp") {

        //  Create the connecter object. Supply it with the session name
        //  so that it can bind the new connection to the session once
        //  it is established.
        zmq_connecter_t *connecter = new zmq_connecter_t (
            choose_io_thread (options.affinity), this, options,
            session_name.c_str (), false);
        int rc = connecter->set_address (addr_args.c_str ());
        if (rc != 0) {
            delete connecter;
            return -1;
        }
        send_plug (connecter);
        send_own (this, connecter);

        return 0;
    }

#if defined ZMQ_HAVE_OPENPGM
    if (addr_type == "pgm" || addr_type == "udp") {

        //  If the socket type requires bi-directional communication
        //  multicast is not an option (it is uni-directional).
        if (options.requires_in && options.requires_out) {
            errno = ENOCOMPATPROTO;
            return -1;
        }

        //  For udp, pgm transport with udp encapsulation is used.
        bool udp_encapsulation = false;
        if (addr_type == "udp")
            udp_encapsulation = true;

        if (options.requires_out) {

            //  PGM sender.
            pgm_sender_t *pgm_sender = 
                new pgm_sender_t (choose_io_thread (options.affinity), options, 
                session_name.c_str ());

            int rc = pgm_sender->init (udp_encapsulation, addr_args.c_str ());
            if (rc != 0) {
                delete pgm_sender;
                return -1;
            }

            //  Reserve a sequence number for following 'attach' command.
            session->inc_seqnum ();
            send_attach (session, pgm_sender);
        }
        else if (options.requires_in) {

            //  PGM receiver.
            pgm_receiver_t *pgm_receiver = 
                new pgm_receiver_t (choose_io_thread (options.affinity), options, 
                session_name.c_str ());

            int rc = pgm_receiver->init (udp_encapsulation, addr_args.c_str ());
            if (rc != 0) {
                delete pgm_receiver;
                return -1;
            }

            //  Reserve a sequence number for following 'attach' command.
            session->inc_seqnum ();
            send_attach (session, pgm_receiver);
        }
        else
            zmq_assert (false);

        return 0;
    }
#endif

    //  Unknown protoco.
    errno = EPROTONOSUPPORT;
    return -1;
}

int zmq::socket_base_t::send (::zmq_msg_t *msg_, int flags_)
{
    //  Process pending commands, if any.
    app_thread->process_commands (false, true);

    //  Try to send the message.
    int rc = xsend (msg_, flags_);
    if (rc == 0)
        return 0;

    //  In case of non-blocking send we'll simply propagate
    //  the error - including EAGAIN - upwards.
    if (flags_ & ZMQ_NOBLOCK)
        return -1;

    //  Oops, we couldn't send the message. Wait for the next
    //  command, process it and try to send the message again.
    while (rc != 0) {
        if (errno != EAGAIN)
            return -1;
        app_thread->process_commands (true, false);
        rc = xsend (msg_, flags_);
    }
    return 0;
}

int zmq::socket_base_t::flush ()
{
    return xflush ();
}

int zmq::socket_base_t::recv (::zmq_msg_t *msg_, int flags_)
{
    //  Get the message and return immediately if successfull.
    int rc = xrecv (msg_, flags_);
    if (rc == 0)
        return 0;

    //  If the message cannot be fetched immediately, there are two scenarios.
    //  For non-blocking recv, commands are processed in case there's a revive
    //  command already waiting int a command pipe. If it's not, return EAGAIN.
    //  In blocking scenario, commands are processed over and over again until
    //  we are able to fetch a message.
    if (flags_ & ZMQ_NOBLOCK) {
        if (errno != EAGAIN)
            return -1;
        app_thread->process_commands (false, false);
        ticks = 0;
        rc = xrecv (msg_, flags_);
    }
    else  {
        while (rc != 0) {
            if (errno != EAGAIN)
                return -1;
            app_thread->process_commands (true, false);
            ticks = 0;
            rc = xrecv (msg_, flags_);
        }
    }


    //  Once every inbound_poll_rate messages check for signals and process
    //  incoming commands. This happens only if we are not polling altogether
    //  because there are messages available all the time. If poll occurs,
    //  ticks is set to zero and thus we avoid this code.
    //
    //  Note that 'recv' uses different command throttling algorithm (the one
    //  described above) from the one used by 'send'. This is because counting
    //  ticks is more efficient than doing rdtsc all the time.
    if (++ticks == inbound_poll_rate) {
        app_thread->process_commands (false, false);
        ticks = 0;
    }

    return rc;
}

int zmq::socket_base_t::close ()
{
    shutting_down = true;

    //  Let the thread know that the socket is no longer available.
    app_thread->remove_socket (this);

    //  Pointer to the dispatcher must be retrieved before the socket is
    //  deallocated. Afterwards it is not available.
    dispatcher_t *dispatcher = get_dispatcher ();

    //  Unregister all inproc endpoints associated with this socket.
    //  From this point we are sure that inc_seqnum won't be called again
    //  on this object.
    dispatcher->unregister_endpoints (this);

    //  Wait till all undelivered commands are delivered. This should happen
    //  very quickly. There's no way to wait here for extensive period of time.
    while (processed_seqnum != sent_seqnum.get ())
        app_thread->process_commands (true, false);

    while (true) {

        //  On third pass of the loop there should be no more I/O objects
        //  because all connecters and listerners were destroyed during
        //  the first pass and all engines delivered by delayed 'own' commands
        //  are destroyed during the second pass.
        if (io_objects.empty () && !pending_term_acks)
            break;

        //  Send termination request to all associated I/O objects.
        for (io_objects_t::iterator it = io_objects.begin ();
              it != io_objects.end (); it++)
            send_term (*it);

        //  Move the objects to the list of pending term acks.
        pending_term_acks += io_objects.size ();
        io_objects.clear ();

        //  Process commands till we get all the termination acknowledgements.
        while (pending_term_acks)
            app_thread->process_commands (true, false);
    }

    //  Check whether there are no session leaks.
    sessions_sync.lock ();
    zmq_assert (sessions.empty ());
    sessions_sync.unlock ();

    delete this;

    //  This function must be called after the socket is completely deallocated
    //  as it may cause termination of the whole 0MQ infrastructure.
    dispatcher->destroy_socket ();

    return 0;
}

void zmq::socket_base_t::inc_seqnum ()
{
    //  NB: This function may be called from a different thread!
    sent_seqnum.add (1);
}

zmq::app_thread_t *zmq::socket_base_t::get_thread ()
{
    return app_thread;
}

bool zmq::socket_base_t::has_in ()
{
    return xhas_in ();
}

bool zmq::socket_base_t::has_out ()
{
    return xhas_out ();
}

bool zmq::socket_base_t::register_session (const char *name_,
    session_t *session_)
{
    sessions_sync.lock ();
    bool registered = sessions.insert (std::make_pair (name_, session_)).second;
    sessions_sync.unlock ();
    return registered;
}

bool zmq::socket_base_t::unregister_session (const char *name_)
{
    sessions_sync.lock ();
    sessions_t::iterator it = sessions.find (name_);
    bool unregistered = (it != sessions.end ());
    sessions.erase (it);
    sessions_sync.unlock ();
    return unregistered;
}

zmq::session_t *zmq::socket_base_t::find_session (const char *name_)
{
    sessions_sync.lock ();

    sessions_t::iterator it = sessions.find (name_);
    if (it == sessions.end ()) {
        sessions_sync.unlock ();
        return NULL;
    }

    //  Prepare the session for subsequent attach command.
    it->second->inc_seqnum ();

    sessions_sync.unlock ();
    return it->second;    
}

void zmq::socket_base_t::kill (reader_t *pipe_)
{
    xkill (pipe_);
}

void zmq::socket_base_t::revive (reader_t *pipe_)
{
    xrevive (pipe_);
}

void zmq::socket_base_t::attach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_)
{
    if (inpipe_)
        inpipe_->set_endpoint (this);
    if (outpipe_)
        outpipe_->set_endpoint (this);
    xattach_pipes (inpipe_, outpipe_);
}

void zmq::socket_base_t::detach_inpipe (class reader_t *pipe_)
{
    xdetach_inpipe (pipe_);
    pipe_->set_endpoint (NULL); // ?
}

void zmq::socket_base_t::detach_outpipe (class writer_t *pipe_)
{
    xdetach_outpipe (pipe_);
    pipe_->set_endpoint (NULL); // ?
}

void zmq::socket_base_t::process_own (owned_t *object_)
{
    io_objects.insert (object_);
}

void zmq::socket_base_t::process_bind (owned_t *session_,
    reader_t *in_pipe_, writer_t *out_pipe_)
{
    attach_pipes (in_pipe_, out_pipe_);
}

void zmq::socket_base_t::process_term_req (owned_t *object_)
{
    //  When shutting down we can ignore termination requests from owned
    //  objects. They are going to be terminated anyway.
    if (shutting_down)
        return;

    //  If I/O object is well and alive ask it to terminate.
    io_objects_t::iterator it = std::find (io_objects.begin (),
        io_objects.end (), object_);

    //  If not found, we assume that termination request was already sent to
    //  the object so we can sagely ignore the request.
    if (it == io_objects.end ())
        return;

    pending_term_acks++;
    io_objects.erase (it);
    send_term (object_);
}

void zmq::socket_base_t::process_term_ack ()
{
    zmq_assert (pending_term_acks);
    pending_term_acks--;
}

