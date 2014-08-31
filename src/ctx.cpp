/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#endif

#include <limits>
#include <new>
#include <string.h>

#include "ctx.hpp"
#include "socket_base.hpp"
#include "io_thread.hpp"
#include "reaper.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "msg.hpp"

#ifdef HAVE_LIBSODIUM
#ifdef HAVE_TWEETNACL
#include "randombytes.h"
#else
#include "sodium.h"
#endif
#endif

#define ZMQ_CTX_TAG_VALUE_GOOD 0xabadcafe
#define ZMQ_CTX_TAG_VALUE_BAD  0xdeadbeef

int clipped_maxsocket(int max_requested)
{
    if (max_requested >= zmq::poller_t::max_fds () && zmq::poller_t::max_fds () != -1)
        // -1 because we need room for the reaper mailbox.
        max_requested = zmq::poller_t::max_fds () - 1;

    return max_requested;
}

zmq::ctx_t::ctx_t () :
    tag (ZMQ_CTX_TAG_VALUE_GOOD),
    starting (true),
    terminating (false),
    reaper (NULL),
    slot_count (0),
    slots (NULL),
    max_sockets (clipped_maxsocket (ZMQ_MAX_SOCKETS_DFLT)),
    io_thread_count (ZMQ_IO_THREADS_DFLT),
    ipv6 (false),
    thread_priority (ZMQ_THREAD_PRIORITY_DFLT),
    thread_sched_policy (ZMQ_THREAD_SCHED_POLICY_DFLT)
{
#ifdef HAVE_FORK
    pid = getpid();
#endif
}

bool zmq::ctx_t::check_tag ()
{
    return tag == ZMQ_CTX_TAG_VALUE_GOOD;
}

zmq::ctx_t::~ctx_t ()
{
    //  Check that there are no remaining sockets.
    zmq_assert (sockets.empty ());

    //  Ask I/O threads to terminate. If stop signal wasn't sent to I/O
    //  thread subsequent invocation of destructor would hang-up.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        io_threads [i]->stop ();

    //  Wait till I/O threads actually terminate.
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++)
        delete io_threads [i];

    //  Deallocate the reaper thread object.
    delete reaper;

    //  Deallocate the array of mailboxes. No special work is
    //  needed as mailboxes themselves were deallocated with their
    //  corresponding io_thread/socket objects.
    free (slots);

    //  If we've done any Curve encryption, we may have a file handle
    //  to /dev/urandom open that needs to be cleaned up.
#ifdef HAVE_LIBSODIUM
    randombytes_close();
#endif

    //  Remove the tag, so that the object is considered dead.
    tag = ZMQ_CTX_TAG_VALUE_BAD;
}

int zmq::ctx_t::terminate ()
{
    // Connect up any pending inproc connections, otherwise we will hang
    pending_connections_t copy = pending_connections;
    for (pending_connections_t::iterator p = copy.begin (); p != copy.end (); ++p) {
        zmq::socket_base_t *s = create_socket (ZMQ_PAIR);
        s->bind (p->first.c_str ());
        s->close ();
    }

    slot_sync.lock ();
    if (!starting) {

#ifdef HAVE_FORK
        if (pid != getpid ()) {
            // we are a forked child process. Close all file descriptors
            // inherited from the parent.
            for (sockets_t::size_type i = 0; i != sockets.size (); i++)
                sockets [i]->get_mailbox ()->forked ();

            term_mailbox.forked ();
        }
#endif

        //  Check whether termination was already underway, but interrupted and now
        //  restarted.
        bool restarted = terminating;
        terminating = true;

        //  First attempt to terminate the context.
        if (!restarted) {
            //  First send stop command to sockets so that any blocking calls
            //  can be interrupted. If there are no sockets we can ask reaper
            //  thread to stop.
            for (sockets_t::size_type i = 0; i != sockets.size (); i++)
                sockets [i]->stop ();
            if (sockets.empty ())
                reaper->stop ();
        }
        slot_sync.unlock();

        //  Wait till reaper thread closes all the sockets.
        command_t cmd;
        int rc = term_mailbox.recv (&cmd, -1);
        if (rc == -1 && errno == EINTR)
            return -1;
        errno_assert (rc == 0);
        zmq_assert (cmd.type == command_t::done);
        slot_sync.lock ();
        zmq_assert (sockets.empty ());
    }
    slot_sync.unlock ();

    //  Deallocate the resources.
    delete this;

    return 0;
}

int zmq::ctx_t::shutdown ()
{
    slot_sync.lock ();
    if (!starting && !terminating) {
        terminating = true;

        //  Send stop command to sockets so that any blocking calls
        //  can be interrupted. If there are no sockets we can ask reaper
        //  thread to stop.
        for (sockets_t::size_type i = 0; i != sockets.size (); i++)
            sockets [i]->stop ();
        if (sockets.empty ())
            reaper->stop ();
    }
    slot_sync.unlock ();

    return 0;
}

int zmq::ctx_t::set (int option_, int optval_)
{
    int rc = 0;
    if (option_ == ZMQ_MAX_SOCKETS
    &&  optval_ >= 1 && optval_ == clipped_maxsocket (optval_)) {
        opt_sync.lock ();
        max_sockets = optval_;
        opt_sync.unlock ();
    }
    else
    if (option_ == ZMQ_IO_THREADS && optval_ >= 0) {
        opt_sync.lock ();
        io_thread_count = optval_;
        opt_sync.unlock ();
    }
    else
    if (option_ == ZMQ_IPV6 && optval_ >= 0) {
        opt_sync.lock ();
        ipv6 = (optval_ != 0);
        opt_sync.unlock ();
    }
    else
    if (option_ == ZMQ_THREAD_PRIORITY && optval_ >= 0) {
        opt_sync.lock();
        thread_priority = optval_;
        opt_sync.unlock();
    }
    else
    if (option_ == ZMQ_THREAD_SCHED_POLICY && optval_ >= 0) {
        opt_sync.lock();
        thread_sched_policy = optval_;
        opt_sync.unlock();
    }
    else {
        errno = EINVAL;
        rc = -1;
    }
    return rc;
}

int zmq::ctx_t::get (int option_)
{
    int rc = 0;
    if (option_ == ZMQ_MAX_SOCKETS)
        rc = max_sockets;
    else
    if (option_ == ZMQ_SOCKET_LIMIT)
        rc = clipped_maxsocket (65535);
    else
    if (option_ == ZMQ_IO_THREADS)
        rc = io_thread_count;
    else
    if (option_ == ZMQ_IPV6)
        rc = ipv6;
    else {
        errno = EINVAL;
        rc = -1;
    }
    return rc;
}

zmq::socket_base_t *zmq::ctx_t::create_socket (int type_)
{
    slot_sync.lock ();
    if (unlikely (starting)) {

        starting = false;
        //  Initialise the array of mailboxes. Additional three slots are for
        //  zmq_ctx_term thread and reaper thread.
        opt_sync.lock ();
        int mazmq = max_sockets;
        int ios = io_thread_count;
        opt_sync.unlock ();
        slot_count = mazmq + ios + 2;
        slots = (mailbox_t **) malloc (sizeof (mailbox_t*) * slot_count);
        alloc_assert (slots);

        //  Initialise the infrastructure for zmq_ctx_term thread.
        slots [term_tid] = &term_mailbox;

        //  Create the reaper thread.
        reaper = new (std::nothrow) reaper_t (this, reaper_tid);
        alloc_assert (reaper);
        slots [reaper_tid] = reaper->get_mailbox ();
        reaper->start ();

        //  Create I/O thread objects and launch them.
        for (int i = 2; i != ios + 2; i++) {
            io_thread_t *io_thread = new (std::nothrow) io_thread_t (this, i);
            alloc_assert (io_thread);
            io_threads.push_back (io_thread);
            slots [i] = io_thread->get_mailbox ();
            io_thread->start ();
        }

        //  In the unused part of the slot array, create a list of empty slots.
        for (int32_t i = (int32_t) slot_count - 1;
              i >= (int32_t) ios + 2; i--) {
            empty_slots.push_back (i);
            slots [i] = NULL;
        }
    }

    //  Once zmq_ctx_term() was called, we can't create new sockets.
    if (terminating) {
        slot_sync.unlock ();
        errno = ETERM;
        return NULL;
    }

    //  If max_sockets limit was reached, return error.
    if (empty_slots.empty ()) {
        slot_sync.unlock ();
        errno = EMFILE;
        return NULL;
    }

    //  Choose a slot for the socket.
    uint32_t slot = empty_slots.back ();
    empty_slots.pop_back ();

    //  Generate new unique socket ID.
    int sid = ((int) max_socket_id.add (1)) + 1;

    //  Create the socket and register its mailbox.
    socket_base_t *s = socket_base_t::create (type_, this, slot, sid);
    if (!s) {
        empty_slots.push_back (slot);
        slot_sync.unlock ();
        return NULL;
    }
    sockets.push_back (s);
    slots [slot] = s->get_mailbox ();

    slot_sync.unlock ();
    return s;
}

void zmq::ctx_t::destroy_socket (class socket_base_t *socket_)
{
    slot_sync.lock ();

    //  Free the associated thread slot.
    uint32_t tid = socket_->get_tid ();
    empty_slots.push_back (tid);
    slots [tid] = NULL;

    //  Remove the socket from the list of sockets.
    sockets.erase (socket_);

    //  If zmq_ctx_term() was already called and there are no more socket
    //  we can ask reaper thread to terminate.
    if (terminating && sockets.empty ())
        reaper->stop ();

    slot_sync.unlock ();
}

zmq::object_t *zmq::ctx_t::get_reaper ()
{
    return reaper;
}

void zmq::ctx_t::start_thread (thread_t &thread_, thread_fn *tfn_, void *arg_) const
{
    thread_.start(tfn_, arg_);
    thread_.setSchedulingParameters(thread_priority, thread_sched_policy);
}

void zmq::ctx_t::send_command (uint32_t tid_, const command_t &command_)
{
    slots [tid_]->send (command_);
}

zmq::io_thread_t *zmq::ctx_t::choose_io_thread (uint64_t affinity_)
{
    if (io_threads.empty ())
        return NULL;

    //  Find the I/O thread with minimum load.
    int min_load = -1;
    io_thread_t *selected_io_thread = NULL;
    for (io_threads_t::size_type i = 0; i != io_threads.size (); i++) {
        if (!affinity_ || (affinity_ & (uint64_t (1) << i))) {
            int load = io_threads [i]->get_load ();
            if (selected_io_thread == NULL || load < min_load) {
                min_load = load;
                selected_io_thread = io_threads [i];
            }
        }
    }
    return selected_io_thread;
}

int zmq::ctx_t::register_endpoint (const char *addr_,
        const endpoint_t &endpoint_)
{
    endpoints_sync.lock ();

    const bool inserted = endpoints.insert (
        endpoints_t::value_type (std::string (addr_), endpoint_)).second;

    endpoints_sync.unlock ();

    if (!inserted) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

int zmq::ctx_t::unregister_endpoint (
        const std::string &addr_, socket_base_t *socket_)
{
    endpoints_sync.lock ();

    const endpoints_t::iterator it = endpoints.find (addr_);
    if (it == endpoints.end () || it->second.socket != socket_) {
        endpoints_sync.unlock ();
        errno = ENOENT;
        return -1;
    }

    //  Remove endpoint.
    endpoints.erase (it);

    endpoints_sync.unlock ();

    return 0;
}

void zmq::ctx_t::unregister_endpoints (socket_base_t *socket_)
{
    endpoints_sync.lock ();

    endpoints_t::iterator it = endpoints.begin ();
    while (it != endpoints.end ()) {
        if (it->second.socket == socket_) {
            endpoints_t::iterator to_erase = it;
            ++it;
            endpoints.erase (to_erase);
            continue;
        }
        ++it;
    }

    endpoints_sync.unlock ();
}

zmq::endpoint_t zmq::ctx_t::find_endpoint (const char *addr_)
{
     endpoints_sync.lock ();

     endpoints_t::iterator it = endpoints.find (addr_);
     if (it == endpoints.end ()) {
         endpoints_sync.unlock ();
         errno = ECONNREFUSED;
         endpoint_t empty = {NULL, options_t()};
         return empty;
     }
     endpoint_t endpoint = it->second;

     //  Increment the command sequence number of the peer so that it won't
     //  get deallocated until "bind" command is issued by the caller.
     //  The subsequent 'bind' has to be called with inc_seqnum parameter
     //  set to false, so that the seqnum isn't incremented twice.
     endpoint.socket->inc_seqnum ();

     endpoints_sync.unlock ();
     return endpoint;
}

void zmq::ctx_t::pend_connection (const std::string &addr_,
        const endpoint_t &endpoint_, pipe_t **pipes_)
{
    const pending_connection_t pending_connection =
        {endpoint_, pipes_ [0], pipes_ [1]};

    endpoints_sync.lock ();

    endpoints_t::iterator it = endpoints.find (addr_);
    if (it == endpoints.end ()) {
        // Still no bind.
        endpoint_.socket->inc_seqnum ();
        pending_connections.insert (pending_connections_t::value_type (addr_, pending_connection));
    }
    else
        // Bind has happened in the mean time, connect directly
        connect_inproc_sockets (it->second.socket, it->second.options, pending_connection, connect_side);

    endpoints_sync.unlock ();
}

void zmq::ctx_t::connect_pending (const char *addr_, zmq::socket_base_t *bind_socket_)
{
    endpoints_sync.lock ();

    std::pair<pending_connections_t::iterator, pending_connections_t::iterator> pending = pending_connections.equal_range(addr_);

    for (pending_connections_t::iterator p = pending.first; p != pending.second; ++p)
        connect_inproc_sockets(bind_socket_, endpoints[addr_].options, p->second, bind_side);

    pending_connections.erase(pending.first, pending.second);
    endpoints_sync.unlock ();
}

void zmq::ctx_t::connect_inproc_sockets (zmq::socket_base_t *bind_socket_,
    options_t& bind_options, const pending_connection_t &pending_connection_, side side_)
{
    bind_socket_->inc_seqnum();
    pending_connection_.bind_pipe->set_tid (bind_socket_->get_tid ());

    if (!bind_options.recv_identity) {
        msg_t msg;
        const bool ok = pending_connection_.bind_pipe->read (&msg);
        zmq_assert (ok);
        const int rc = msg.close ();
        errno_assert (rc == 0);
    }


    int sndhwm = 0;
    if (pending_connection_.endpoint.options.sndhwm != 0 && bind_options.rcvhwm != 0)
        sndhwm = pending_connection_.endpoint.options.sndhwm + bind_options.rcvhwm;

    int rcvhwm = 0;
    if (pending_connection_.endpoint.options.rcvhwm != 0 && bind_options.sndhwm != 0)
        rcvhwm = pending_connection_.endpoint.options.rcvhwm + bind_options.sndhwm;

    bool conflate = pending_connection_.endpoint.options.conflate &&
            (pending_connection_.endpoint.options.type == ZMQ_DEALER ||
             pending_connection_.endpoint.options.type == ZMQ_PULL ||
             pending_connection_.endpoint.options.type == ZMQ_PUSH ||
             pending_connection_.endpoint.options.type == ZMQ_PUB ||
             pending_connection_.endpoint.options.type == ZMQ_SUB);

    int hwms [2] = {conflate? -1 : sndhwm, conflate? -1 : rcvhwm};
    pending_connection_.connect_pipe->set_hwms(hwms [1], hwms [0]);
    pending_connection_.bind_pipe->set_hwms(hwms [0], hwms [1]);

    if (side_ == bind_side) {
        command_t cmd;
        cmd.type = command_t::bind;
        cmd.args.bind.pipe = pending_connection_.bind_pipe;
        bind_socket_->process_command (cmd);
        bind_socket_->send_inproc_connected (pending_connection_.endpoint.socket);
    }
    else
        pending_connection_.connect_pipe->send_bind (bind_socket_, pending_connection_.bind_pipe, false);

    if (pending_connection_.endpoint.options.recv_identity) {
        msg_t id;
        int rc = id.init_size (bind_options.identity_size);
        errno_assert (rc == 0);
        memcpy (id.data (), bind_options.identity, bind_options.identity_size);
        id.set_flags (msg_t::identity);
        bool written = pending_connection_.bind_pipe->write (&id);
        zmq_assert (written);
        pending_connection_.bind_pipe->flush ();
    }
}

//  The last used socket ID, or 0 if no socket was used so far. Note that this
//  is a global variable. Thus, even sockets created in different contexts have
//  unique IDs.
zmq::atomic_counter_t zmq::ctx_t::max_socket_id;
