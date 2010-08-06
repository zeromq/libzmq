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
#include <string>
#include <algorithm>

#include "../include/zmq.h"

#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#if defined _MSC_VER
#include <intrin.h>
#endif
#else
#include <unistd.h>
#endif

#include "socket_base.hpp"
#include "zmq_listener.hpp"
#include "zmq_connecter.hpp"
#include "io_thread.hpp"
#include "session.hpp"
#include "config.hpp"
#include "owned.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "ctx.hpp"
#include "platform.hpp"
#include "pgm_sender.hpp"
#include "pgm_receiver.hpp"
#include "likely.hpp"
#include "pair.hpp"
#include "pub.hpp"
#include "sub.hpp"
#include "req.hpp"
#include "rep.hpp"
#include "pull.hpp"
#include "push.hpp"
#include "xreq.hpp"
#include "xrep.hpp"
#include "uuid.hpp"

//  If the RDTSC is available we use it to prevent excessive
//  polling for commands. The nice thing here is that it will work on any
//  system with x86 architecture and gcc or MSVC compiler.
#if (defined __GNUC__ && (defined __i386__ || defined __x86_64__)) ||\
    (defined _MSC_VER && (defined _M_IX86 || defined _M_X64))
#define ZMQ_DELAY_COMMANDS
#endif

zmq::socket_base_t *zmq::socket_base_t::create (int type_, class ctx_t *parent_,
    uint32_t slot_)
{
    socket_base_t *s = NULL;
    switch (type_) {

    case ZMQ_PAIR:
        s = new (std::nothrow) pair_t (parent_, slot_);
        break;
    case ZMQ_PUB:
        s = new (std::nothrow) pub_t (parent_, slot_);
        break;
    case ZMQ_SUB:
        s = new (std::nothrow) sub_t (parent_, slot_);
        break;
    case ZMQ_REQ:
        s = new (std::nothrow) req_t (parent_, slot_);
        break;
    case ZMQ_REP:
        s = new (std::nothrow) rep_t (parent_, slot_);
        break;
    case ZMQ_XREQ:
        s = new (std::nothrow) xreq_t (parent_, slot_);
        break;
    case ZMQ_XREP:
        s = new (std::nothrow) xrep_t (parent_, slot_);
        break;     
    case ZMQ_PULL:
        s = new (std::nothrow) pull_t (parent_, slot_);
        break;
    case ZMQ_PUSH:
        s = new (std::nothrow) push_t (parent_, slot_);
        break;
    default:
        errno = EINVAL;
        return NULL;
    }
    zmq_assert (s);
    return s;
}

zmq::socket_base_t::socket_base_t (ctx_t *parent_, uint32_t slot_) :
    object_t (parent_, slot_),
    zombie (false),
    last_processing_time (0),
    pending_term_acks (0),
    ticks (0),
    rcvmore (false),
    sent_seqnum (0),
    processed_seqnum (0),
    next_ordinal (1)
{
}

zmq::socket_base_t::~socket_base_t ()
{
}

zmq::signaler_t *zmq::socket_base_t::get_signaler ()
{
    return &signaler;
}

void zmq::socket_base_t::stop ()
{
    //  Called by ctx when it is terminated (zmq_term).
    //  'stop' command is sent from the threads that called zmq_term to
    //  the thread owning the socket. This way, blocking call in the
    //  owner thread can be interrupted.
    send_stop ();
}

void zmq::socket_base_t::attach_pipes (class reader_t *inpipe_,
    class writer_t *outpipe_, const blob_t &peer_identity_)
{
    // If the peer haven't specified it's identity, let's generate one.
    if (peer_identity_.size ()) {
        xattach_pipes (inpipe_, outpipe_, peer_identity_);
    }
    else {
        blob_t identity (1, 0);
        identity.append (uuid_t ().to_blob (), uuid_t::uuid_blob_len);
        xattach_pipes (inpipe_, outpipe_, identity);
    }
}

int zmq::socket_base_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

    //  First, check whether specific socket type overloads the option.
    int rc = xsetsockopt (option_, optval_, optvallen_);
    if (rc == 0 || errno != EINVAL)
        return rc;

    //  If the socket type doesn't support the option, pass it to
    //  the generic option parser.
    return options.setsockopt (option_, optval_, optvallen_);
}

int zmq::socket_base_t::getsockopt (int option_, void *optval_,
    size_t *optvallen_)
{
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

    if (option_ == ZMQ_RCVMORE) {
        if (*optvallen_ < sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        *((int64_t*) optval_) = rcvmore ? 1 : 0;
        *optvallen_ = sizeof (int64_t);
        return 0;
    }

    if (option_ == ZMQ_FD) {
        if (*optvallen_ < sizeof (fd_t)) {
            errno = EINVAL;
            return -1;
        }
        *((fd_t*) optval_) = signaler.get_fd ();
        *optvallen_ = sizeof (fd_t);
        return 0;
    }

    if (option_ == ZMQ_EVENTS) {
        if (*optvallen_ < sizeof (uint32_t)) {
            errno = EINVAL;
            return -1;
        }
        process_commands(false, false);
        *((uint32_t*) optval_) = 0;
        if (has_out ())
            *((uint32_t*) optval_) |= ZMQ_POLLOUT;
        if (has_in ())
            *((uint32_t*) optval_) |= ZMQ_POLLIN;
        *optvallen_ = sizeof (uint32_t);
        return 0;
    }

    return options.getsockopt (option_, optval_, optvallen_);
}

int zmq::socket_base_t::bind (const char *addr_)
{
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

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

    if (addr_type == "tcp" || addr_type == "ipc") {

#if defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS
        if (addr_type == "ipc") {
            errno = EPROTONOSUPPORT;
            return -1;
        }
#endif

        zmq_listener_t *listener = new (std::nothrow) zmq_listener_t (
            choose_io_thread (options.affinity), this, options);
        zmq_assert (listener);
        int rc = listener->set_address (addr_type.c_str(), addr_args.c_str ());
        if (rc != 0) {
            delete listener;
            return -1;
        }

        send_plug (listener);
        send_own (this, listener);
        return 0;
    }

#if defined ZMQ_HAVE_OPENPGM
    if (addr_type == "pgm" || addr_type == "epgm") {
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
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

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

        //  TODO: inproc connect is specific with respect to creating pipes
        //  as there's no 'reconnect' functionality implemented. Once that
        //  is in place we should follow generic pipe creation algorithm.

        //  Find the peer socket.
        socket_base_t *peer = find_endpoint (addr_args.c_str ());
        if (!peer)
            return -1;

        reader_t *inpipe_reader = NULL;
        writer_t *inpipe_writer = NULL;
        reader_t *outpipe_reader = NULL;
        writer_t *outpipe_writer = NULL;
 
        //  Create inbound pipe, if required.
        if (options.requires_in)
            create_pipe (this, peer, options.hwm, options.swap,
                &inpipe_reader, &inpipe_writer);

        //  Create outbound pipe, if required.
        if (options.requires_out)
            create_pipe (peer, this, options.hwm, options.swap,
                &outpipe_reader, &outpipe_writer);

        //  Attach the pipes to this socket object.
        attach_pipes (inpipe_reader, outpipe_writer, blob_t ());

        //  Attach the pipes to the peer socket. Note that peer's seqnum
        //  was incremented in find_endpoint function. The callee is notified
        //  about the fact via the last parameter.
        send_bind (peer, outpipe_reader, inpipe_writer,
            options.identity, false);

        return 0;
    }

    //  Create unnamed session.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    session_t *session = new (std::nothrow) session_t (io_thread,
        this, options);
    zmq_assert (session);

    //  If 'immediate connect' feature is required, we'll create the pipes
    //  to the session straight away. Otherwise, they'll be created by the
    //  session once the connection is established.
    if (options.immediate_connect) {

        reader_t *inpipe_reader = NULL;
        writer_t *inpipe_writer = NULL;
        reader_t *outpipe_reader = NULL;
        writer_t *outpipe_writer = NULL;

        //  Create inbound pipe, if required.
        if (options.requires_in)
            create_pipe (this, session, options.hwm, options.swap,
                &inpipe_reader, &inpipe_writer);

        //  Create outbound pipe, if required.
        if (options.requires_out)
            create_pipe (session, this, options.hwm, options.swap,
                &outpipe_reader, &outpipe_writer);

        //  Attach the pipes to the socket object.
        attach_pipes (inpipe_reader, outpipe_writer, blob_t ());

        //  Attach the pipes to the session object.
        session->attach_pipes (outpipe_reader, inpipe_writer, blob_t ());
    }

    //  Activate the session.
    send_plug (session);
    send_own (this, session);

    if (addr_type == "tcp" || addr_type == "ipc") {

#if defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS
        //  Windows named pipes are not compatible with Winsock API.
        //  There's no UNIX domain socket implementation on OpenVMS.
        if (addr_type == "ipc") {
            errno = EPROTONOSUPPORT;
            return -1;
        }
#endif

        //  Create the connecter object. Supply it with the session name
        //  so that it can bind the new connection to the session once
        //  it is established.
        zmq_connecter_t *connecter = new (std::nothrow) zmq_connecter_t (
            choose_io_thread (options.affinity), this, options,
            session->get_ordinal (), false);
        zmq_assert (connecter);
        int rc = connecter->set_address (addr_type.c_str(), addr_args.c_str ());
        if (rc != 0) {
            delete connecter;
            return -1;
        }
        send_plug (connecter);
        send_own (this, connecter);

        return 0;
    }

#if defined ZMQ_HAVE_OPENPGM
    if (addr_type == "pgm" || addr_type == "epgm") {

        //  If the socket type requires bi-directional communication
        //  multicast is not an option (it is uni-directional).
        if (options.requires_in && options.requires_out) {
            errno = ENOCOMPATPROTO;
            return -1;
        }

        //  For epgm, pgm transport with UDP encapsulation is used.
        bool udp_encapsulation = (addr_type == "epgm");

        //  At this point we'll create message pipes to the session straight
        //  away. There's no point in delaying it as no concept of 'connect'
        //  exists with PGM anyway.
        if (options.requires_out) {

            //  PGM sender.
            pgm_sender_t *pgm_sender =  new (std::nothrow) pgm_sender_t (
                choose_io_thread (options.affinity), options);
            zmq_assert (pgm_sender);

            int rc = pgm_sender->init (udp_encapsulation, addr_args.c_str ());
            if (rc != 0) {
                delete pgm_sender;
                return -1;
            }

            send_attach (session, pgm_sender, blob_t ());
        }
        else if (options.requires_in) {

            //  PGM receiver.
            pgm_receiver_t *pgm_receiver =  new (std::nothrow) pgm_receiver_t (
                choose_io_thread (options.affinity), options);
            zmq_assert (pgm_receiver);

            int rc = pgm_receiver->init (udp_encapsulation, addr_args.c_str ());
            if (rc != 0) {
                delete pgm_receiver;
                return -1;
            }

            send_attach (session, pgm_receiver, blob_t ());
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
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

    //  Process pending commands, if any.
    process_commands (false, true);
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

    //  At this point we impose the MORE flag on the message.
    if (flags_ & ZMQ_SNDMORE)
        msg_->flags |= ZMQ_MSG_MORE;

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
        process_commands (true, false);
        if (unlikely (zombie)) {
            errno = ETERM;
            return -1;
        }
        rc = xsend (msg_, flags_);
    }
    return 0;
}

int zmq::socket_base_t::recv (::zmq_msg_t *msg_, int flags_)
{
    if (unlikely (zombie)) {
        errno = ETERM;
        return -1;
    }

    //  Get the message.
    int rc = xrecv (msg_, flags_);
    int err = errno;

    //  Once every inbound_poll_rate messages check for signals and process
    //  incoming commands. This happens only if we are not polling altogether
    //  because there are messages available all the time. If poll occurs,
    //  ticks is set to zero and thus we avoid this code.
    //
    //  Note that 'recv' uses different command throttling algorithm (the one
    //  described above) from the one used by 'send'. This is because counting
    //  ticks is more efficient than doing rdtsc all the time.
    if (++ticks == inbound_poll_rate) {
        process_commands (false, false);
        if (unlikely (zombie)) {
            errno = ETERM;
            return -1;
        }
        ticks = 0;
    }

    //  If we have the message, return immediately.
    if (rc == 0) {
        rcvmore = msg_->flags & ZMQ_MSG_MORE;
        if (rcvmore)
            msg_->flags &= ~ZMQ_MSG_MORE;
        return 0;
    }

    //  If we don't have the message, restore the original cause of the problem.
    errno = err;

    //  If the message cannot be fetched immediately, there are two scenarios.
    //  For non-blocking recv, commands are processed in case there's a revive
    //  command already waiting int a command pipe. If it's not, return EAGAIN.
    if (flags_ & ZMQ_NOBLOCK) {
        if (errno != EAGAIN)
            return -1;
        process_commands (false, false);
        if (unlikely (zombie)) {
            errno = ETERM;
            return -1;
        }
        ticks = 0;

        rc = xrecv (msg_, flags_);
        if (rc == 0) {
            rcvmore = msg_->flags & ZMQ_MSG_MORE;
            if (rcvmore)
                msg_->flags &= ~ZMQ_MSG_MORE;
        }
        return rc;
    }

    //  In blocking scenario, commands are processed over and over again until
    //  we are able to fetch a message.
    while (rc != 0) {
        if (errno != EAGAIN)
            return -1;
        process_commands (true, false);
        if (unlikely (zombie)) {
            errno = ETERM;
            return -1;
        }
        rc = xrecv (msg_, flags_);
        ticks = 0;
    }

    rcvmore = msg_->flags & ZMQ_MSG_MORE;
    if (rcvmore)
        msg_->flags &= ~ZMQ_MSG_MORE;
    return 0;
}

int zmq::socket_base_t::close ()
{
    //  Socket becomes a zombie. From now on all new arrived pipes (bind
    //  command) and I/O objects (own command) are immediately terminated.
    //  Also, any further requests form I/O object termination are ignored
    //  (we are going to shut them down anyway -- this way we assure that
    //  we do so once only).
    zombie = true;

    //  Unregister all inproc endpoints associated with this socket.
    //  Doing this we make sure that no new pipes from other sockets (inproc)
    //  will be initiated. However, there may be some inproc pipes already
    //  on the fly, but not yet received by this socket. To get finished
    //  with them we'll do the subsequent waiting from on-the-fly commands.
    //  This should happen very quickly. There's no way to block here for
    //  extensive period of time.
    unregister_endpoints (this);
    while (processed_seqnum != sent_seqnum.get ())
        process_commands (true, false);
    //  TODO: My feeling is that the above has to be done in the dezombification
    //  loop, otherwise we may end up with number of i/o object dropping to zero
    //  even though there are more i/o objects on the way.

    //  The above process ensures that only pipes that will arrive from now on
    //  are those initiated by sessions. These in turn have a nice property of
    //  not arriving totally asynchronously. When a session -- being an I/O
    //  object -- acknowledges its termination we are 100% sure that we'll get
    //  no new pipe from it.

    //  Start termination of all the pipes presently associated with the socket.
    xterm_pipes ();

    //  Send termination request to all associated I/O objects.
    //  Start waiting for the acks. Note that the actual waiting is not done
    //  in this function. Rather it is done in delayed manner as socket is
    //  being dezombified. The reason is that I/O object shutdown can take
    //  considerable amount of time in case there's still a lot of data to
    //  push to the network.
    for (io_objects_t::iterator it = io_objects.begin ();
          it != io_objects.end (); it++)
        send_term (*it);
    pending_term_acks += io_objects.size ();
    io_objects.clear ();

    //  Note that new I/O objects may arrive even in zombie state (say new
    //  session initiated by a listener object), however, in such case number
    //  of pending acks never drops to zero. Here's the scenario: We have an
    //  pending ack for the listener object. Then 'own' commands arrives from
    //  the listener notifying the socket about new session. It immediately
    //  triggers termination request and number of of pending acks if
    //  incremented. Then term_acks arrives from the listener. Number of pending
    //  acks is decremented. Later on, the session itself will ack its
    //  termination. During the process, number of pending acks never dropped
    //  to zero and thus the socket remains safely in the zombie state.

    //  Transfer the ownership of the socket from this application thread
    //  to the context which will take care of the rest of shutdown process.
    zombify (this);

    return 0;
}

void zmq::socket_base_t::inc_seqnum ()
{
    //  Be aware: This function may be called from a different thread!
    sent_seqnum.add (1);
}

bool zmq::socket_base_t::has_in ()
{
    return xhas_in ();
}

bool zmq::socket_base_t::has_out ()
{
    return xhas_out ();
}

bool zmq::socket_base_t::register_session (const blob_t &peer_identity_,
    session_t *session_)
{
    sessions_sync.lock ();
    bool registered = named_sessions.insert (
        std::make_pair (peer_identity_, session_)).second;
    sessions_sync.unlock ();
    return registered;
}

void zmq::socket_base_t::unregister_session (const blob_t &peer_identity_)
{
    sessions_sync.lock ();
    named_sessions_t::iterator it = named_sessions.find (peer_identity_);
    zmq_assert (it != named_sessions.end ());
    named_sessions.erase (it);
    sessions_sync.unlock ();
}

zmq::session_t *zmq::socket_base_t::find_session (const blob_t &peer_identity_)
{
    sessions_sync.lock ();
    named_sessions_t::iterator it = named_sessions.find (peer_identity_);
    if (it == named_sessions.end ()) {
        sessions_sync.unlock ();
        return NULL;
    }
    session_t *session = it->second;

    //  Prepare the session for subsequent attach command.
    session->inc_seqnum ();

    sessions_sync.unlock ();
    return session;    
}

uint64_t zmq::socket_base_t::register_session (session_t *session_)
{
    sessions_sync.lock ();
    uint64_t ordinal = next_ordinal;
    next_ordinal++;
    unnamed_sessions.insert (std::make_pair (ordinal, session_));
    sessions_sync.unlock ();
    return ordinal;
}

void zmq::socket_base_t::unregister_session (uint64_t ordinal_)
{
    sessions_sync.lock ();
    unnamed_sessions_t::iterator it = unnamed_sessions.find (ordinal_);
    zmq_assert (it != unnamed_sessions.end ());
    unnamed_sessions.erase (it);
    sessions_sync.unlock ();
}

zmq::session_t *zmq::socket_base_t::find_session (uint64_t ordinal_)
{
    sessions_sync.lock ();

    unnamed_sessions_t::iterator it = unnamed_sessions.find (ordinal_);
    if (it == unnamed_sessions.end ()) {
        sessions_sync.unlock ();
        return NULL;
    }
    session_t *session = it->second;

    //  Prepare the session for subsequent attach command.
    session->inc_seqnum ();

    sessions_sync.unlock ();
    return session; 
}

bool zmq::socket_base_t::dezombify ()
{
    zmq_assert (zombie);

    //  Process any commands from other threads/sockets that may be available
    //  at the moment.
    process_commands (false, false);

    //  If there are no more pipes attached and there are no more I/O objects
    //  owned by the socket, we can kill the zombie.
    if (!pending_term_acks && !xhas_pipes ()) {

        //  If all objects have acknowledged their termination there should
        //  definitely be no I/O object remaining in the list.
        zmq_assert (io_objects.empty ());

        //  Check whether there are no session leaks.
        sessions_sync.lock ();
        zmq_assert (named_sessions.empty ());
        zmq_assert (unnamed_sessions.empty ());
        sessions_sync.unlock ();

        //  Deallocate all the resources tied to this socket.
        delete this;

        //  Notify the caller about the fact that the zombie is finally dead.
        return true;
    }

    //  The zombie remains undead.
    return false;
}

void zmq::socket_base_t::process_commands (bool block_, bool throttle_)
{
    bool received;
    command_t cmd;
    if (block_) {
        received = signaler.recv (&cmd, true);
        zmq_assert (received);
    }
    else {

#if defined ZMQ_DELAY_COMMANDS
        //  Optimised version of command processing - it doesn't have to check
        //  for incoming commands each time. It does so only if certain time
        //  elapsed since last command processing. Command delay varies
        //  depending on CPU speed: It's ~1ms on 3GHz CPU, ~2ms on 1.5GHz CPU
        //  etc. The optimisation makes sense only on platforms where getting
        //  a timestamp is a very cheap operation (tens of nanoseconds).
        if (throttle_) {

            //  Get timestamp counter.
#if defined __GNUC__
            uint32_t low;
            uint32_t high;
            __asm__ volatile ("rdtsc" : "=a" (low), "=d" (high));
            uint64_t current_time = (uint64_t) high << 32 | low;
#elif defined _MSC_VER
            uint64_t current_time = __rdtsc ();
#else
#error
#endif

            //  Check whether certain time have elapsed since last command
            //  processing.
            if (current_time - last_processing_time <= max_command_delay)
                return;
            last_processing_time = current_time;
        }
#endif

        //  Check whether there are any commands pending for this thread.
        received = signaler.recv (&cmd, false);
    }

    //  Process all the commands available at the moment.
    while (received) {
        cmd.destination->process_command (cmd);
        received = signaler.recv (&cmd, false);
    }
}

void zmq::socket_base_t::process_stop ()
{
    //  Here, someone have called zmq_term while the socket was still alive.
    //  We'll zombify it so that any blocking call is interrupted and any
    //  further attempt to use the socket will return ETERM. The user is still
    //  responsible for calling zmq_close on the socket though!
    zombie = true;
}

void zmq::socket_base_t::process_own (owned_t *object_)
{
    //  If the socket is already being shut down, new owned objects are
    //  immediately asked to terminate.
    if (zombie) {
        send_term (object_);
        pending_term_acks++;
        return;
    }

    io_objects.insert (object_);
}

void zmq::socket_base_t::process_bind (reader_t *in_pipe_, writer_t *out_pipe_,
    const blob_t &peer_identity_)
{
    //  If the socket is already being shut down, the termination process on
    //  the new pipes is started immediately. However, they are still attached
    //  as to let the process finish in a decent manner.
    if (unlikely (zombie)) {
        if (in_pipe_)
            in_pipe_->terminate ();
        if (out_pipe_)
            out_pipe_->terminate ();
    }

    attach_pipes (in_pipe_, out_pipe_, peer_identity_);
}

void zmq::socket_base_t::process_term_req (owned_t *object_)
{
    //  When shutting down we can ignore termination requests from owned
    //  objects. It means the termination request was already sent to
    //  the object.
    if (zombie)
        return;

    //  If I/O object is well and alive ask it to terminate.
    io_objects_t::iterator it = std::find (io_objects.begin (),
        io_objects.end (), object_);

    //  If not found, we assume that termination request was already sent to
    //  the object so we can safely ignore the request.
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

void zmq::socket_base_t::process_seqnum ()
{
    processed_seqnum++;
}

int zmq::socket_base_t::xsetsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    errno = EINVAL;
    return -1;
}

bool zmq::socket_base_t::xhas_out ()
{
    return false;
}

int zmq::socket_base_t::xsend (zmq_msg_t *msg_, int options_)
{
    errno = ENOTSUP;
    return -1;
}

bool zmq::socket_base_t::xhas_in ()
{
    return false;
}

int zmq::socket_base_t::xrecv (zmq_msg_t *msg_, int options_)
{
    errno = ENOTSUP;
    return -1;
}

