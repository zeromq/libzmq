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

#include <iostream>

#include <string>
#include <algorithm>

#include "../c/zmq.h"

#include "socket_base.hpp"
#include "app_thread.hpp"
#include "dispatcher.hpp"
#include "zmq_listener.hpp"
#include "zmq_connecter.hpp"
#include "msg_content.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "config.hpp"
#include "owned.hpp"
#include "uuid.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "platform.hpp"
#include "pgm_sender.hpp"

zmq::socket_base_t::socket_base_t (app_thread_t *parent_, int type_) :
    object_t (parent_),
    type (type_),
    current (0),
    active (0),
    pending_term_acks (0),
    ticks (0),
    app_thread (parent_),
    shutting_down (false),
    index (-1)
{
}

zmq::socket_base_t::~socket_base_t ()
{
    shutting_down = true;

    //  Ask all pipes to terminate.
    for (in_pipes_t::iterator it = in_pipes.begin ();
          it != in_pipes.end (); it++)
        (*it)->term ();
    in_pipes.clear ();
    for (out_pipes_t::iterator it = out_pipes.begin ();
          it != out_pipes.end (); it++)
        (*it)->term ();
    out_pipes.clear ();

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
}

int zmq::socket_base_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    switch (option_) {

    case ZMQ_HWM:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.hwm = *((int64_t*) optval_);
        return 0;

    case ZMQ_LWM:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.lwm = *((int64_t*) optval_);
        return 0;

    case ZMQ_SWAP:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.swap = *((int64_t*) optval_);
        return 0;

    case ZMQ_AFFINITY:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.affinity = (uint64_t) *((int64_t*) optval_);
        return 0;

    case ZMQ_IDENTITY:
        options.identity.assign ((const char*) optval_, optvallen_);
        return 0;

    case ZMQ_SUBSCRIBE:
    case ZMQ_UNSUBSCRIBE:
        errno = EFAULT;
        return -1;

    case ZMQ_RATE:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.rate = (uint32_t) *((int64_t*) optval_);
        return 0;
        
    case ZMQ_RECOVERY_IVL:
        if (optvallen_ != sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        options.recovery_ivl = (uint32_t) *((int64_t*) optval_);
        return 0;

    default:
        errno = EINVAL;
        return -1;
    }
}

int zmq::socket_base_t::bind (const char *addr_)
{
    zmq_listener_t *listener = new zmq_listener_t (
        choose_io_thread (options.affinity), this, options);
    int rc = listener->set_address (addr_);
    if (rc != 0)
        return -1;

    send_plug (listener);
    send_own (this, listener);
    return 0;
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

    //  Create the session.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    session_t *session = new session_t (io_thread, this, session_name.c_str (),
        options);
    zmq_assert (session);

    //  Create inbound pipe.
    pipe_t *in_pipe = new pipe_t (this, session, options.hwm, options.lwm);
    zmq_assert (in_pipe);
    in_pipe->reader.set_endpoint (this);
    session->attach_outpipe (&in_pipe->writer);
    in_pipes.push_back (&in_pipe->reader);
    in_pipes.back ()->set_index (active);
    in_pipes [active]->set_index (in_pipes.size () - 1);
    std::swap (in_pipes.back (), in_pipes [active]);
    active++;

    //  Create outbound pipe.
    pipe_t *out_pipe = new pipe_t (session, this, options.hwm, options.lwm);
    zmq_assert (out_pipe);
    out_pipe->writer.set_endpoint (this);
    session->attach_inpipe (&out_pipe->reader);
    out_pipes.push_back (&out_pipe->writer);

    //  Activate the session.
    send_plug (session);
    send_own (this, session);

    if (addr_type == "tcp") {

        //  Create the connecter object. Supply it with the session name so that
        //  it can bind the new connection to the session once it is established.
        zmq_connecter_t *connecter = new zmq_connecter_t (
            choose_io_thread (options.affinity), this, options,
            session_name.c_str ());
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
    if (addr_type == "pgm") {
        
        switch (type) {
        case ZMQ_PUB:
        {
            pgm_sender_t *pgm_sender = 
                new pgm_sender_t (choose_io_thread (options.affinity), options, 
                session_name.c_str ());

            int rc = pgm_sender->init (addr_args.c_str ());
            if (rc != 0) {
                delete pgm_sender;
                return -1;
            }
    
            //  Reserve a sequence number for following 'attach' command.
            session->inc_seqnum ();
            send_attach (session, pgm_sender);

            pgm_sender = NULL;

            break;
        }
        case ZMQ_SUB:
            zmq_assert (false);
            break;
        default:
            errno = EINVAL;
            return -1;
        }

        return 0;
    }
#endif

    //  Unknown address type.
    errno = EFAULT;
    return -1;
}

int zmq::socket_base_t::send (::zmq_msg_t *msg_, int flags_)
{
    //  Process pending commands, if any.
    app_thread->process_commands (false, true);

    //  Try to send the message.
    bool sent = distribute (msg_, !(flags_ & ZMQ_NOFLUSH));

    if (!(flags_ & ZMQ_NOBLOCK)) {

        //  Oops, we couldn't send the message. Wait for the next
        //  command, process it and try to send the message again.
        while (!sent) {
            app_thread->process_commands (true, false);
            sent = distribute (msg_, !(flags_ & ZMQ_NOFLUSH));
        }
    }
    else if (!sent) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}

int zmq::socket_base_t::flush ()
{
    for (out_pipes_t::iterator it = out_pipes.begin (); it != out_pipes.end ();
          it++)
        (*it)->flush ();

    return 0;
}

int zmq::socket_base_t::recv (::zmq_msg_t *msg_, int flags_)
{
    //  If the message cannot be fetched immediately, there are two scenarios.
    //  For non-blocking recv, commands are processed in case there's a message
    //  already waiting we don't know about. If it's not, return EAGAIN.
    //  In blocking scenario, commands are processed over and over again until
    //  we are able to fetch a message.
    bool fetched = fetch (msg_);
    if (!fetched) {
        if (flags_ & ZMQ_NOBLOCK) {
            app_thread->process_commands (false, false);
            fetched = fetch (msg_);
        }
        else  {
            while (!fetched) {
                app_thread->process_commands (true, false);
                ticks = 0;
                fetched = fetch (msg_);
            }
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

    if (!fetched) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}

int zmq::socket_base_t::close ()
{
    app_thread->remove_socket (this);

    //  Pointer to the dispatcher must be retrieved before the socket is
    //  deallocated. Afterwards it is not available.
    dispatcher_t *dispatcher = get_dispatcher ();
    delete this;

    //  This function must be called after the socket is completely deallocated
    //  as it may cause termination of the whole 0MQ infrastructure.
    dispatcher->destroy_socket ();

    return 0;
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

void zmq::socket_base_t::attach_inpipe (class reader_t *pipe_)
{
    pipe_->set_endpoint (this);
    in_pipes.push_back (pipe_);
    in_pipes.back ()->set_index (active);
    in_pipes [active]->set_index (in_pipes.size () - 1);
    std::swap (in_pipes.back (), in_pipes [active]);
    active++;
}

void zmq::socket_base_t::attach_outpipe (class writer_t *pipe_)
{
    pipe_->set_endpoint (this);
    out_pipes.push_back (pipe_);
    pipe_->set_index (out_pipes.size () - 1);
}

void zmq::socket_base_t::revive (reader_t *pipe_)
{
    //  Move the pipe to the list of active pipes.
    in_pipes_t::size_type index = (in_pipes_t::size_type) pipe_->get_index ();
    in_pipes [index]->set_index (active);
    in_pipes [active]->set_index (index);    
    std::swap (in_pipes [index], in_pipes [active]);
    active++;
}

void zmq::socket_base_t::detach_inpipe (class reader_t *pipe_)
{
    //  Remove the pipe from the list of inbound pipes.
    in_pipes_t::size_type index = (in_pipes_t::size_type) pipe_->get_index ();
    if (index < active) {
        in_pipes [index]->set_index (active - 1);
        in_pipes [active - 1]->set_index (index);
        std::swap (in_pipes [index], in_pipes [active - 1]);
        active--;
        index = active;
    }
    in_pipes [index]->set_index (in_pipes.size () - 1);
    in_pipes [in_pipes.size () - 1]->set_index (index);
    std::swap (in_pipes [index], in_pipes [in_pipes.size () - 1]);
    in_pipes.pop_back ();
}

void zmq::socket_base_t::detach_outpipe (class writer_t *pipe_)
{
    out_pipes_t::size_type index = (out_pipes_t::size_type) pipe_->get_index ();
    out_pipes [index]->set_index (out_pipes.size () - 1);
    out_pipes [out_pipes.size () - 1]->set_index (index);
    std::swap (out_pipes [index], out_pipes [out_pipes.size () - 1]);
    out_pipes.pop_back ();
}

void zmq::socket_base_t::set_index (int index_)
{
    index = index_;
}

int zmq::socket_base_t::get_index ()
{
    zmq_assert (index != -1);
    return index;
}

void zmq::socket_base_t::process_own (owned_t *object_)
{
    io_objects.insert (object_);
}

void zmq::socket_base_t::process_bind (owned_t *session_,
    reader_t *in_pipe_, writer_t *out_pipe_)
{
    zmq_assert (in_pipe_);
    attach_inpipe (in_pipe_);
    zmq_assert (out_pipe_);
    attach_outpipe (out_pipe_);
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

bool zmq::socket_base_t::distribute (zmq_msg_t *msg_, bool flush_)
{
    int pipes_count = out_pipes.size ();

    //  If there are no pipes available, simply drop the message.
    if (pipes_count == 0) {
        int rc = zmq_msg_close (msg_);
        zmq_assert (rc == 0);
        rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return true;
    }

    //  First check whether all pipes are available for writing.
    for (out_pipes_t::iterator it = out_pipes.begin (); it != out_pipes.end ();
          it++)
        if (!(*it)->check_write (zmq_msg_size (msg_)))
            return false;

    msg_content_t *content = (msg_content_t*) msg_->content;

    //  For VSMs the copying is straighforward.
    if (content == (msg_content_t*) ZMQ_VSM) {
        for (out_pipes_t::iterator it = out_pipes.begin ();
              it != out_pipes.end (); it++) {
            (*it)->write (msg_);
            if (flush_)
                (*it)->flush ();
        }
        int rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return true;
    }

    //  Optimisation for the case when there's only a single pipe
    //  to send the message to - no refcount adjustment i.e. no atomic
    //  operations are needed.
    if (pipes_count == 1) {
        (*out_pipes.begin ())->write (msg_);
        if (flush_)
            (*out_pipes.begin ())->flush ();
        int rc = zmq_msg_init (msg_);
        zmq_assert (rc == 0);
        return true;
    }

    //  There are at least 2 destinations for the message. That means we have
    //  to deal with reference counting. First add N-1 references to
    //  the content (we are holding one reference anyway, that's why -1).
    if (msg_->shared)
        content->refcnt.add (pipes_count - 1);
    else {
        content->refcnt.set (pipes_count);
        msg_->shared = true;
    }

    //  Push the message to all destinations.
    for (out_pipes_t::iterator it = out_pipes.begin (); it != out_pipes.end ();
          it++) {
        (*it)->write (msg_);
        if (flush_)
            (*it)->flush ();
    }

    //  Detach the original message from the data buffer.
    int rc = zmq_msg_init (msg_);
    zmq_assert (rc == 0);

    return true;
}

bool zmq::socket_base_t::fetch (zmq_msg_t *msg_)
{
    //  Deallocate old content of the message.
    zmq_msg_close (msg_);

    //  Round-robin over the pipes to get next message.
    for (int count = active; count != 0; count--) {

        bool fetched = in_pipes [current]->read (msg_);

        //  If there's no message in the pipe, move it to the list of
        //  non-active pipes.
        if (!fetched) {
            in_pipes [current]->set_index (active - 1);
            in_pipes [active - 1]->set_index (current);
            std::swap (in_pipes [current], in_pipes [active - 1]);
            active--;
        }

        current ++;
        if (current >= active)
            current = 0;

        if (fetched)
            return true;
    }

    //  No message is available. Initialise the output parameter
    //  to be a 0-byte message.
    zmq_msg_init (msg_);
    return false;
}
