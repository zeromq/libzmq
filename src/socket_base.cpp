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

#include <new>
#include <string>
#include <algorithm>

#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#if defined _MSC_VER
#if defined WINCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#endif
#endif
#else
#include <unistd.h>
#endif

#include "socket_base.hpp"
#include "tcp_listener.hpp"
#include "ipc_listener.hpp"
#include "tcp_connecter.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "ctx.hpp"
#include "platform.hpp"
#include "likely.hpp"
#include "msg.hpp"
#include "address.hpp"
#include "ipc_address.hpp"
#include "tcp_address.hpp"
#ifdef ZMQ_HAVE_OPENPGM
#include "pgm_socket.hpp"
#endif

#include "pair.hpp"
#include "pub.hpp"
#include "sub.hpp"
#include "req.hpp"
#include "rep.hpp"
#include "pull.hpp"
#include "push.hpp"
#include "dealer.hpp"
#include "router.hpp"
#include "xpub.hpp"
#include "xsub.hpp"

bool zmq::socket_base_t::check_tag ()
{
    return tag == 0xbaddecaf;
}

zmq::socket_base_t *zmq::socket_base_t::create (int type_, class ctx_t *parent_,
    uint32_t tid_, int sid_)
{
    socket_base_t *s = NULL;
    switch (type_) {

    case ZMQ_PAIR:
        s = new (std::nothrow) pair_t (parent_, tid_, sid_);
        break;
    case ZMQ_PUB:
        s = new (std::nothrow) pub_t (parent_, tid_, sid_);
        break;
    case ZMQ_SUB:
        s = new (std::nothrow) sub_t (parent_, tid_, sid_);
        break;
    case ZMQ_REQ:
        s = new (std::nothrow) req_t (parent_, tid_, sid_);
        break;
    case ZMQ_REP:
        s = new (std::nothrow) rep_t (parent_, tid_, sid_);
        break;
    case ZMQ_DEALER:
        s = new (std::nothrow) dealer_t (parent_, tid_, sid_);
        break;
    case ZMQ_ROUTER:
        s = new (std::nothrow) router_t (parent_, tid_, sid_);
        break;     
    case ZMQ_PULL:
        s = new (std::nothrow) pull_t (parent_, tid_, sid_);
        break;
    case ZMQ_PUSH:
        s = new (std::nothrow) push_t (parent_, tid_, sid_);
        break;
    case ZMQ_XPUB:
        s = new (std::nothrow) xpub_t (parent_, tid_, sid_);
        break;
    case ZMQ_XSUB:
        s = new (std::nothrow) xsub_t (parent_, tid_, sid_);
        break;
    default:
        errno = EINVAL;
        return NULL;
    }
    alloc_assert (s);
    return s;
}

zmq::socket_base_t::socket_base_t (ctx_t *parent_, uint32_t tid_, int sid_) :
    own_t (parent_, tid_),
    tag (0xbaddecaf),
    ctx_terminated (false),
    destroyed (false),
    last_tsc (0),
    ticks (0),
    rcvmore (false),
    monitor_socket (NULL),
    monitor_events (0)
{
    options.socket_id = sid_;
}

zmq::socket_base_t::~socket_base_t ()
{
    stop_monitor ();
    zmq_assert (destroyed);
}

zmq::mailbox_t *zmq::socket_base_t::get_mailbox ()
{
    return &mailbox;
}

void zmq::socket_base_t::stop ()
{
    //  Called by ctx when it is terminated (zmq_term).
    //  'stop' command is sent from the threads that called zmq_term to
    //  the thread owning the socket. This way, blocking call in the
    //  owner thread can be interrupted.
    send_stop ();
}

int zmq::socket_base_t::parse_uri (const char *uri_,
                        std::string &protocol_, std::string &address_)
{
    zmq_assert (uri_ != NULL);

    std::string uri (uri_);
    std::string::size_type pos = uri.find ("://");
    if (pos == std::string::npos) {
        errno = EINVAL;
        return -1;
    }
    protocol_ = uri.substr (0, pos);
    address_ = uri.substr (pos + 3);
    
    if (protocol_.empty () || address_.empty ()) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int zmq::socket_base_t::check_protocol (const std::string &protocol_)
{
    //  First check out whether the protcol is something we are aware of.
    if (protocol_ != "inproc" && protocol_ != "ipc" && protocol_ != "tcp" &&
          protocol_ != "pgm" && protocol_ != "epgm") {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    //  If 0MQ is not compiled with OpenPGM, pgm and epgm transports
    //  are not avaialble.
#if !defined ZMQ_HAVE_OPENPGM
    if (protocol_ == "pgm" || protocol_ == "epgm") {
        errno = EPROTONOSUPPORT;
        return -1;
    }
#endif

    //  IPC transport is not available on Windows and OpenVMS.
#if defined ZMQ_HAVE_WINDOWS || defined ZMQ_HAVE_OPENVMS
    if (protocol_ == "ipc") {
        //  Unknown protocol.
        errno = EPROTONOSUPPORT;
        return -1;
    }
#endif

    //  Check whether socket type and transport protocol match.
    //  Specifically, multicast protocols can't be combined with
    //  bi-directional messaging patterns (socket types).
    if ((protocol_ == "pgm" || protocol_ == "epgm") &&
          options.type != ZMQ_PUB && options.type != ZMQ_SUB &&
          options.type != ZMQ_XPUB && options.type != ZMQ_XSUB) {
        errno = ENOCOMPATPROTO;
        return -1;
    }

    //  Protocol is available.
    return 0;
}

void zmq::socket_base_t::attach_pipe (pipe_t *pipe_, bool icanhasall_)
{
    //  First, register the pipe so that we can terminate it later on.
    pipe_->set_event_sink (this);
    pipes.push_back (pipe_);
    
    //  Let the derived socket type know about new pipe.
    xattach_pipe (pipe_, icanhasall_);

    //  If the socket is already being closed, ask any new pipes to terminate
    //  straight away.
    if (is_terminating ()) {
        register_term_acks (1);
        pipe_->terminate (false);
    }
}

int zmq::socket_base_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    if (unlikely (ctx_terminated)) {
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
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    if (option_ == ZMQ_RCVMORE) {
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = rcvmore ? 1 : 0;
        *optvallen_ = sizeof (int);
        return 0;
    }

    if (option_ == ZMQ_FD) {
        if (*optvallen_ < sizeof (fd_t)) {
            errno = EINVAL;
            return -1;
        }
        *((fd_t*) optval_) = mailbox.get_fd ();
        *optvallen_ = sizeof (fd_t);
        return 0;
    }

    if (option_ == ZMQ_EVENTS) {
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        int rc = process_commands (0, false);
        if (rc != 0 && (errno == EINTR || errno == ETERM))
            return -1;
        errno_assert (rc == 0);
        *((int*) optval_) = 0;
        if (has_out ())
            *((int*) optval_) |= ZMQ_POLLOUT;
        if (has_in ())
            *((int*) optval_) |= ZMQ_POLLIN;
        *optvallen_ = sizeof (int);
        return 0;
    }

    return options.getsockopt (option_, optval_, optvallen_);
}

int zmq::socket_base_t::bind (const char *addr_)
{
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Process pending commands, if any.
    int rc = process_commands (0, false);
    if (unlikely (rc != 0))
        return -1;

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    rc = parse_uri (addr_, protocol, address);
    if (rc != 0)
        return -1;

    rc = check_protocol (protocol);
    if (rc != 0)
        return -1;

    if (protocol == "inproc") {
        endpoint_t endpoint = {this, options};
        int rc = register_endpoint (addr_, endpoint);
        if (rc == 0) {
            // Save last endpoint URI
            options.last_endpoint.assign (addr_);
        }
        return rc;
    }

    if (protocol == "pgm" || protocol == "epgm") {
        //  For convenience's sake, bind can be used interchageable with
        //  connect for PGM and EPGM transports.
        return connect (addr_);
    }

    //  Remaining trasnports require to be run in an I/O thread, so at this
    //  point we'll choose one.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    if (!io_thread) {
        errno = EMTHREAD;
        return -1;
    }

    if (protocol == "tcp") {
        tcp_listener_t *listener = new (std::nothrow) tcp_listener_t (
            io_thread, this, options);
        alloc_assert (listener);
        int rc = listener->set_address (address.c_str ());
        if (rc != 0) {
            delete listener;
            event_bind_failed (address, zmq_errno());
            return -1;
        }

        // Save last endpoint URI
        listener->get_address (options.last_endpoint);

        add_endpoint (addr_, (own_t *) listener);
        return 0;
    }

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    if (protocol == "ipc") {
        ipc_listener_t *listener = new (std::nothrow) ipc_listener_t (
            io_thread, this, options);
        alloc_assert (listener);
        int rc = listener->set_address (address.c_str ());
        if (rc != 0) {
            delete listener;
            event_bind_failed (address, zmq_errno());
            return -1;
        }

        // Save last endpoint URI
        listener->get_address (options.last_endpoint);

        add_endpoint (addr_, (own_t *) listener);
        return 0;
    }
#endif

    zmq_assert (false);
    return -1;
}

int zmq::socket_base_t::connect (const char *addr_)
{
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Process pending commands, if any.
    int rc = process_commands (0, false);
    if (unlikely (rc != 0))
        return -1;

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    rc = parse_uri (addr_, protocol, address);
    if (rc != 0)
        return -1;

    rc = check_protocol (protocol);
    if (rc != 0)
        return -1;

    if (protocol == "inproc") {

        //  TODO: inproc connect is specific with respect to creating pipes
        //  as there's no 'reconnect' functionality implemented. Once that
        //  is in place we should follow generic pipe creation algorithm.

        //  Find the peer endpoint.
        endpoint_t peer = find_endpoint (addr_);
        if (!peer.socket)
            return -1;

        // The total HWM for an inproc connection should be the sum of
        // the binder's HWM and the connector's HWM.
        int sndhwm = 0;
        if (options.sndhwm != 0 && peer.options.rcvhwm != 0)
            sndhwm = options.sndhwm + peer.options.rcvhwm;
        int rcvhwm = 0;
        if (options.rcvhwm != 0 && peer.options.sndhwm != 0)
            rcvhwm = options.rcvhwm + peer.options.sndhwm;

        //  Create a bi-directional pipe to connect the peers.
        object_t *parents [2] = {this, peer.socket};
        pipe_t *pipes [2] = {NULL, NULL};
        int hwms [2] = {sndhwm, rcvhwm};
        bool delays [2] = {options.delay_on_disconnect, options.delay_on_close};
        int rc = pipepair (parents, pipes, hwms, delays);
        errno_assert (rc == 0);

        //  Attach local end of the pipe to this socket object.
        attach_pipe (pipes [0]);

        //  If required, send the identity of the local socket to the peer.
        if (peer.options.recv_identity) {
            msg_t id;
            rc = id.init_size (options.identity_size);
            errno_assert (rc == 0);
            memcpy (id.data (), options.identity, options.identity_size);
            id.set_flags (msg_t::identity);
            bool written = pipes [0]->write (&id);
            zmq_assert (written);
            pipes [0]->flush ();
        }

        //  If required, send the identity of the peer to the local socket.
        if (options.recv_identity) {
            msg_t id;
            rc = id.init_size (peer.options.identity_size);
            errno_assert (rc == 0);
            memcpy (id.data (), peer.options.identity, peer.options.identity_size);
            id.set_flags (msg_t::identity);
            bool written = pipes [1]->write (&id);
            zmq_assert (written);
            pipes [1]->flush ();
        }

        //  Attach remote end of the pipe to the peer socket. Note that peer's
        //  seqnum was incremented in find_endpoint function. We don't need it
        //  increased here.
        send_bind (peer.socket, pipes [1], false);

        // Save last endpoint URI
        options.last_endpoint.assign (addr_);

        // remember inproc connections for disconnect
        inprocs.insert (inprocs_t::value_type (std::string (addr_), pipes[0]));

        return 0;
    }

    //  Choose the I/O thread to run the session in.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    if (!io_thread) {
        errno = EMTHREAD;
        return -1;
    }

    address_t *paddr = new (std::nothrow) address_t (protocol, address);
    alloc_assert (paddr);

    //  Resolve address (if needed by the protocol)
    if (protocol == "tcp") {
        paddr->resolved.tcp_addr = new (std::nothrow) tcp_address_t ();
        alloc_assert (paddr->resolved.tcp_addr);
        int rc = paddr->resolved.tcp_addr->resolve (
            address.c_str (), false, options.ipv4only ? true : false);
        if (rc != 0) {
            delete paddr;
            return -1;
        }
    }
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    else
    if (protocol == "ipc") {
        paddr->resolved.ipc_addr = new (std::nothrow) ipc_address_t ();
        alloc_assert (paddr->resolved.ipc_addr);
        int rc = paddr->resolved.ipc_addr->resolve (address.c_str ());
        if (rc != 0) {
            delete paddr;
            return -1;
        }
    }
#endif
#ifdef ZMQ_HAVE_OPENPGM
    if (protocol == "pgm" || protocol == "epgm") {
        struct pgm_addrinfo_t *res = NULL;
        uint16_t port_number = 0;
        int rc = pgm_socket_t::init_address(address.c_str(), &res, &port_number);
        if (res != NULL)
            pgm_freeaddrinfo (res);
        if (rc != 0 || port_number == 0)
            return -1;
    }
#endif
    //  Create session.
    session_base_t *session = session_base_t::create (io_thread, true, this,
        options, paddr);
    errno_assert (session);

    //  PGM does not support subscription forwarding; ask for all data to be
    //  sent to this pipe.
    bool icanhasall = protocol == "pgm" || protocol == "epgm";

    if (options.delay_attach_on_connect != 1 || icanhasall) {
        //  Create a bi-directional pipe.
        object_t *parents [2] = {this, session};
        pipe_t *pipes [2] = {NULL, NULL};
        int hwms [2] = {options.sndhwm, options.rcvhwm};
        bool delays [2] = {options.delay_on_disconnect, options.delay_on_close};
        rc = pipepair (parents, pipes, hwms, delays);
        errno_assert (rc == 0);

        //  Attach local end of the pipe to the socket object.
        attach_pipe (pipes [0], icanhasall);

        //  Attach remote end of the pipe to the session object later on.
        session->attach_pipe (pipes [1]);
    }

    //  Save last endpoint URI
    paddr->to_string (options.last_endpoint);

    add_endpoint (addr_, (own_t *) session);
    return 0;
}

void zmq::socket_base_t::add_endpoint (const char *addr_, own_t *endpoint_)
{
    //  Activate the session. Make it a child of this socket.
    launch_child (endpoint_);
    endpoints.insert (endpoints_t::value_type (std::string (addr_), endpoint_));
}

int zmq::socket_base_t::term_endpoint (const char *addr_)
{
    //  Check whether the library haven't been shut down yet.
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Check whether endpoint address passed to the function is valid.
    if (unlikely (!addr_)) {
        errno = EINVAL;
        return -1;
    }

    //  Process pending commands, if any, since there could be pending unprocessed process_own()'s
    //  (from launch_child() for example) we're asked to terminate now.
    int rc = process_commands (0, false);
    if (unlikely (rc != 0))
        return -1;

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    rc = parse_uri (addr_, protocol, address);
    if (rc != 0)
        return -1;

    rc = check_protocol (protocol);
    if (rc != 0)
        return -1;

    // Disconnect an inproc socket
    if (protocol == "inproc") {
        std::pair <inprocs_t::iterator, inprocs_t::iterator> range = inprocs.equal_range (std::string (addr_));
        if (range.first == range.second) {
            errno = ENOENT;
            return -1;
        }
	
        for (inprocs_t::iterator it = range.first; it != range.second; ++it)
            it->second->terminate(true);
        inprocs.erase (range.first, range.second);
        return 0;
    }


    //  Find the endpoints range (if any) corresponding to the addr_ string.
    std::pair <endpoints_t::iterator, endpoints_t::iterator> range = endpoints.equal_range (std::string (addr_));
    if (range.first == range.second) {
        errno = ENOENT;
        return -1;
    }

    for (endpoints_t::iterator it = range.first; it != range.second; ++it)
        term_child (it->second);
    endpoints.erase (range.first, range.second);
    return 0;
}

int zmq::socket_base_t::send (msg_t *msg_, int flags_)
{
    //  Check whether the library haven't been shut down yet.
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Check whether message passed to the function is valid.
    if (unlikely (!msg_ || !msg_->check ())) {
        errno = EFAULT;
        return -1;
    }

    //  Process pending commands, if any.
    int rc = process_commands (0, true);
    if (unlikely (rc != 0))
        return -1;

    //  Clear any user-visible flags that are set on the message.
    msg_->reset_flags (msg_t::more);

    //  At this point we impose the flags on the message.
    if (flags_ & ZMQ_SNDMORE)
        msg_->set_flags (msg_t::more);

    //  Try to send the message.
    rc = xsend (msg_, flags_);
    if (rc == 0)
        return 0;
    if (unlikely (errno != EAGAIN))
        return -1;

    //  In case of non-blocking send we'll simply propagate
    //  the error - including EAGAIN - up the stack.
    if (flags_ & ZMQ_DONTWAIT || options.sndtimeo == 0)
        return -1;

    //  Compute the time when the timeout should occur.
    //  If the timeout is infite, don't care. 
    int timeout = options.sndtimeo;
    uint64_t end = timeout < 0 ? 0 : (clock.now_ms () + timeout);

    //  Oops, we couldn't send the message. Wait for the next
    //  command, process it and try to send the message again.
    //  If timeout is reached in the meantime, return EAGAIN.
    while (true) {
        if (unlikely (process_commands (timeout, false) != 0))
            return -1;
        rc = xsend (msg_, flags_);
        if (rc == 0)
            break;
        if (unlikely (errno != EAGAIN))
            return -1;
        if (timeout > 0) {
            timeout = (int) (end - clock.now_ms ());
            if (timeout <= 0) {
                errno = EAGAIN;
                return -1;
            }
        }
    }
    return 0;
}

int zmq::socket_base_t::recv (msg_t *msg_, int flags_)
{
    //  Check whether the library haven't been shut down yet.
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Check whether message passed to the function is valid.
    if (unlikely (!msg_ || !msg_->check ())) {
        errno = EFAULT;
        return -1;
    }

    //  Once every inbound_poll_rate messages check for signals and process
    //  incoming commands. This happens only if we are not polling altogether
    //  because there are messages available all the time. If poll occurs,
    //  ticks is set to zero and thus we avoid this code.
    //
    //  Note that 'recv' uses different command throttling algorithm (the one
    //  described above) from the one used by 'send'. This is because counting
    //  ticks is more efficient than doing RDTSC all the time.
    if (++ticks == inbound_poll_rate) {
        if (unlikely (process_commands (0, false) != 0))
            return -1;
        ticks = 0;
    }

    //  Get the message.
    int rc = xrecv (msg_, flags_);
    if (unlikely (rc != 0 && errno != EAGAIN))
        return -1;

    //  If we have the message, return immediately.
    if (rc == 0) {
        extract_flags (msg_);
        return 0;
    }

    //  If the message cannot be fetched immediately, there are two scenarios.
    //  For non-blocking recv, commands are processed in case there's an
    //  activate_reader command already waiting int a command pipe.
    //  If it's not, return EAGAIN.
    if (flags_ & ZMQ_DONTWAIT || options.rcvtimeo == 0) {
        if (unlikely (process_commands (0, false) != 0))
            return -1;
        ticks = 0;

        rc = xrecv (msg_, flags_);
        if (rc < 0)
            return rc;
        extract_flags (msg_);
        return 0;
    }

    //  Compute the time when the timeout should occur.
    //  If the timeout is infite, don't care. 
    int timeout = options.rcvtimeo;
    uint64_t end = timeout < 0 ? 0 : (clock.now_ms () + timeout);

    //  In blocking scenario, commands are processed over and over again until
    //  we are able to fetch a message.
    bool block = (ticks != 0);
    while (true) {
        if (unlikely (process_commands (block ? timeout : 0, false) != 0))
            return -1;
        rc = xrecv (msg_, flags_);
        if (rc == 0) {
            ticks = 0;
            break;
        }
        if (unlikely (errno != EAGAIN))
            return -1;
        block = true;
        if (timeout > 0) {
            timeout = (int) (end - clock.now_ms ());
            if (timeout <= 0) {
                errno = EAGAIN;
                return -1;
            }
        }
    }

    extract_flags (msg_);
    return 0;
}

int zmq::socket_base_t::close ()
{
    //  Mark the socket as dead
    tag = 0xdeadbeef;
    
    //  Transfer the ownership of the socket from this application thread
    //  to the reaper thread which will take care of the rest of shutdown
    //  process.
    send_reap (this);

    return 0;
}

bool zmq::socket_base_t::has_in ()
{
    return xhas_in ();
}

bool zmq::socket_base_t::has_out ()
{
    return xhas_out ();
}

void zmq::socket_base_t::start_reaping (poller_t *poller_)
{
    //  Plug the socket to the reaper thread.
    poller = poller_;
    handle = poller->add_fd (mailbox.get_fd (), this);
    poller->set_pollin (handle);

    //  Initialise the termination and check whether it can be deallocated
    //  immediately.
    terminate ();
    check_destroy ();
}

int zmq::socket_base_t::process_commands (int timeout_, bool throttle_)
{
    int rc;
    command_t cmd;
    if (timeout_ != 0) {

        //  If we are asked to wait, simply ask mailbox to wait.
        rc = mailbox.recv (&cmd, timeout_);
    }
    else {

        //  If we are asked not to wait, check whether we haven't processed
        //  commands recently, so that we can throttle the new commands.

        //  Get the CPU's tick counter. If 0, the counter is not available.
        uint64_t tsc = zmq::clock_t::rdtsc ();

        //  Optimised version of command processing - it doesn't have to check
        //  for incoming commands each time. It does so only if certain time
        //  elapsed since last command processing. Command delay varies
        //  depending on CPU speed: It's ~1ms on 3GHz CPU, ~2ms on 1.5GHz CPU
        //  etc. The optimisation makes sense only on platforms where getting
        //  a timestamp is a very cheap operation (tens of nanoseconds).
        if (tsc && throttle_) {

            //  Check whether TSC haven't jumped backwards (in case of migration
            //  between CPU cores) and whether certain time have elapsed since
            //  last command processing. If it didn't do nothing.
            if (tsc >= last_tsc && tsc - last_tsc <= max_command_delay)
                return 0;
            last_tsc = tsc;
        }

        //  Check whether there are any commands pending for this thread.
        rc = mailbox.recv (&cmd, 0);
    }

    //  Process all available commands.
    while (rc == 0) {
        cmd.destination->process_command (cmd);
        rc = mailbox.recv (&cmd, 0);
    }

    if (errno == EINTR)
        return -1;

    zmq_assert (errno == EAGAIN);

    if (ctx_terminated) {
        errno = ETERM;
        return -1;
    }

    return 0;
}

void zmq::socket_base_t::process_stop ()
{
    //  Here, someone have called zmq_term while the socket was still alive.
    //  We'll remember the fact so that any blocking call is interrupted and any
    //  further attempt to use the socket will return ETERM. The user is still
    //  responsible for calling zmq_close on the socket though!
    stop_monitor ();
    ctx_terminated = true;
}

void zmq::socket_base_t::process_bind (pipe_t *pipe_)
{
    attach_pipe (pipe_);
}

void zmq::socket_base_t::process_term (int linger_)
{
    //  Unregister all inproc endpoints associated with this socket.
    //  Doing this we make sure that no new pipes from other sockets (inproc)
    //  will be initiated.
    unregister_endpoints (this);

    //  Ask all attached pipes to terminate.
    for (pipes_t::size_type i = 0; i != pipes.size (); ++i)
        pipes [i]->terminate (false);
    register_term_acks ((int) pipes.size ());

    //  Continue the termination process immediately.
    own_t::process_term (linger_);
}

void zmq::socket_base_t::process_destroy ()
{
    destroyed = true;
}

int zmq::socket_base_t::xsetsockopt (int, const void *, size_t)
{
    errno = EINVAL;
    return -1;
}

bool zmq::socket_base_t::xhas_out ()
{
    return false;
}

int zmq::socket_base_t::xsend (msg_t *, int)
{
    errno = ENOTSUP;
    return -1;
}

bool zmq::socket_base_t::xhas_in ()
{
    return false;
}

int zmq::socket_base_t::xrecv (msg_t *, int)
{
    errno = ENOTSUP;
    return -1;
}

void zmq::socket_base_t::xread_activated (pipe_t *)
{
    zmq_assert (false);
}
void zmq::socket_base_t::xwrite_activated (pipe_t *)
{
    zmq_assert (false);
}

void zmq::socket_base_t::xhiccuped (pipe_t *)
{
    zmq_assert (false);
}

void zmq::socket_base_t::in_event ()
{
    //  This function is invoked only once the socket is running in the context
    //  of the reaper thread. Process any commands from other threads/sockets
    //  that may be available at the moment. Ultimately, the socket will
    //  be destroyed.
    process_commands (0, false);
    check_destroy ();
}

void zmq::socket_base_t::out_event ()
{
    zmq_assert (false);
}

void zmq::socket_base_t::timer_event (int)
{
    zmq_assert (false);
}

void zmq::socket_base_t::check_destroy ()
{
    //  If the object was already marked as destroyed, finish the deallocation.
    if (destroyed) {

        //  Remove the socket from the reaper's poller.
        poller->rm_fd (handle);

        //  Remove the socket from the context.
        destroy_socket (this);

        //  Notify the reaper about the fact.
        send_reaped ();

        //  Deallocate.
        own_t::process_destroy ();
    }
}

void zmq::socket_base_t::read_activated (pipe_t *pipe_)
{
    xread_activated (pipe_);
}

void zmq::socket_base_t::write_activated (pipe_t *pipe_)
{
    xwrite_activated (pipe_);
}

void zmq::socket_base_t::hiccuped (pipe_t *pipe_)
{
    if (options.delay_attach_on_connect == 1)
        pipe_->terminate (false);
    else
        // Notify derived sockets of the hiccup
        xhiccuped (pipe_);
}

void zmq::socket_base_t::terminated (pipe_t *pipe_)
{
    //  Notify the specific socket type about the pipe termination.
    xterminated (pipe_);

    // Remove pipe from inproc pipes
    for (inprocs_t::iterator it = inprocs.begin(); it != inprocs.end(); ++it) {
        if (it->second == pipe_) {
            inprocs.erase(it);
            break;
        }
    }    

    //  Remove the pipe from the list of attached pipes and confirm its
    //  termination if we are already shutting down.
    pipes.erase (pipe_);
    if (is_terminating ())
        unregister_term_ack ();
}

void zmq::socket_base_t::extract_flags (msg_t *msg_)
{
    //  Test whether IDENTITY flag is valid for this socket type.
    if (unlikely (msg_->flags () & msg_t::identity))
        zmq_assert (options.recv_identity);
  
    //  Remove MORE flag.
    rcvmore = msg_->flags () & msg_t::more ? true : false;
}

int zmq::socket_base_t::monitor (const char *addr_, int events_)
{
    int rc;
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    // Support deregistering monitoring endpoints as well
    if (addr_ == NULL) {
        stop_monitor ();
        return 0;
    }

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    rc = parse_uri (addr_, protocol, address);
    if (rc != 0)
        return -1;

    rc = check_protocol (protocol);
    if (rc != 0)
        return -1;

    // Event notification only supported over inproc://
    if (protocol != "inproc") {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    // Register events to monitor
    monitor_events = events_;
    monitor_socket = zmq_socket (get_ctx (), ZMQ_PAIR);
    if (monitor_socket == NULL)
        return -1;

    // Never block context termination on pending event messages
    int linger = 0;
    rc = zmq_setsockopt (monitor_socket, ZMQ_LINGER, &linger, sizeof (linger));
    if (rc == -1)
         stop_monitor ();

    // Spawn the monitor socket endpoint
    rc = zmq_bind (monitor_socket, addr_);
    if (rc == -1)
         stop_monitor ();
    return rc;
}

void zmq::socket_base_t::event_connected (std::string &addr_, int fd_)
{
    if (monitor_events & ZMQ_EVENT_CONNECTED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_CONNECTED;
        event.data.connected.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.connected.addr, addr_);
        event.data.connected.fd = fd_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_connect_delayed (std::string &addr_, int err_)
{
    if (monitor_events & ZMQ_EVENT_CONNECT_DELAYED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_CONNECT_DELAYED;
        event.data.connect_delayed.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.connect_delayed.addr, addr_);
        event.data.connect_delayed.err = err_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_connect_retried (std::string &addr_, int interval_)
{
    if (monitor_events & ZMQ_EVENT_CONNECT_RETRIED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_CONNECT_RETRIED;
        event.data.connect_retried.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.connect_retried.addr, addr_);
        event.data.connect_retried.interval = interval_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_listening (std::string &addr_, int fd_)
{
    if (monitor_events & ZMQ_EVENT_LISTENING) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_LISTENING;
        event.data.listening.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.listening.addr, addr_);
        event.data.listening.fd = fd_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_bind_failed (std::string &addr_, int err_)
{
    if (monitor_events & ZMQ_EVENT_BIND_FAILED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_BIND_FAILED;
        event.data.bind_failed.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.bind_failed.addr, addr_);
        event.data.bind_failed.err = err_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_accepted (std::string &addr_, int fd_)
{
    if (monitor_events & ZMQ_EVENT_ACCEPTED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_ACCEPTED;
        event.data.accepted.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.accepted.addr, addr_);
        event.data.accepted.fd = fd_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_accept_failed (std::string &addr_, int err_)
{
    if (monitor_events & ZMQ_EVENT_ACCEPT_FAILED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_ACCEPT_FAILED;
        event.data.accept_failed.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.accept_failed.addr, addr_);
        event.data.accept_failed.err= err_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_closed (std::string &addr_, int fd_)
{
    if (monitor_events & ZMQ_EVENT_CLOSED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_CLOSED;
        event.data.closed.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.closed.addr, addr_);
        event.data.closed.fd = fd_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_close_failed (std::string &addr_, int err_)
{
    if (monitor_events & ZMQ_EVENT_CLOSE_FAILED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_CLOSE_FAILED;
        event.data.close_failed.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.close_failed.addr, addr_);
        event.data.close_failed.err = err_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::event_disconnected (std::string &addr_, int fd_)
{
    if (monitor_events & ZMQ_EVENT_DISCONNECTED) {
        zmq_event_t event;
        event.event = ZMQ_EVENT_DISCONNECTED;
        event.data.disconnected.addr = (char *) malloc (addr_.size () + 1);
        copy_monitor_address (event.data.disconnected.addr, addr_);
        event.data.disconnected.fd = fd_;
        monitor_event (event);
    }
}

void zmq::socket_base_t::copy_monitor_address (char *dest_, std::string &src_)
{
    alloc_assert (dest_);
    dest_[src_.size ()] = 0;
    memcpy (dest_, src_.c_str (), src_.size ());
}

void zmq::socket_base_t::monitor_event (zmq_event_t event_)
{
    if (monitor_socket) {
        zmq_msg_t msg;
        void *event_data = malloc (sizeof (event_));
        alloc_assert (event_data);
        memcpy (event_data, &event_, sizeof (event_));
        zmq_msg_init_data (&msg, event_data, sizeof (event_), zmq_free_event, NULL);
        zmq_sendmsg (monitor_socket, &msg, 0);
        zmq_msg_close (&msg);
    }
}

void zmq::socket_base_t::stop_monitor()
{
    if (monitor_socket) {
        zmq_close (monitor_socket);
        monitor_socket = NULL;
        monitor_events = 0;
    }
}
