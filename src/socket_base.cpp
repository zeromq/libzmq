/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include <new>
#include <string>
#include <algorithm>

#include "macros.hpp"

#if defined ZMQ_HAVE_WINDOWS
#if defined _MSC_VER
#if defined _WIN32_WCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#endif
#endif
#else
#include <unistd.h>
#include <ctype.h>
#endif

#include "socket_base.hpp"
#include "tcp_listener.hpp"
#include "ipc_listener.hpp"
#include "tipc_listener.hpp"
#include "tcp_connecter.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "pipe.hpp"
#include "err.hpp"
#include "ctx.hpp"
#include "likely.hpp"
#include "msg.hpp"
#include "address.hpp"
#include "ipc_address.hpp"
#include "tcp_address.hpp"
#include "udp_address.hpp"
#include "tipc_address.hpp"
#include "mailbox.hpp"
#include "mailbox_safe.hpp"

#if defined ZMQ_HAVE_VMCI
#include "vmci_address.hpp"
#include "vmci_listener.hpp"
#endif

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
#include "stream.hpp"
#include "server.hpp"
#include "client.hpp"
#include "radio.hpp"
#include "dish.hpp"
#include "gather.hpp"
#include "scatter.hpp"
#include "dgram.hpp"



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
        case ZMQ_STREAM:
            s = new (std::nothrow) stream_t (parent_, tid_, sid_);
            break;
        case ZMQ_SERVER:
            s = new (std::nothrow) server_t (parent_, tid_, sid_);
            break;
        case ZMQ_CLIENT:
            s = new (std::nothrow) client_t (parent_, tid_, sid_);
            break;
        case ZMQ_RADIO:
            s = new (std::nothrow) radio_t (parent_, tid_, sid_);
            break;
        case ZMQ_DISH:
            s = new (std::nothrow) dish_t (parent_, tid_, sid_);
            break;
        case ZMQ_GATHER:
            s = new (std::nothrow) gather_t (parent_, tid_, sid_);
            break;
        case ZMQ_SCATTER:
            s = new (std::nothrow) scatter_t (parent_, tid_, sid_);
            break;
        case ZMQ_DGRAM:
            s = new (std::nothrow) dgram_t (parent_, tid_, sid_);
            break;
        default:
            errno = EINVAL;
            return NULL;
    }

    alloc_assert (s);

    if (s->mailbox == NULL) {
        s->destroyed = true;
        LIBZMQ_DELETE(s);
        return NULL;
    }

    return s;
}

zmq::socket_base_t::socket_base_t (ctx_t *parent_, uint32_t tid_, int sid_, bool thread_safe_) :
    own_t (parent_, tid_),
    tag (0xbaddecaf),
    ctx_terminated (false),
    destroyed (false),
    poller(NULL),
    handle((poller_t::handle_t)NULL),
    last_tsc (0),
    ticks (0),
    rcvmore (false),
    monitor_socket (NULL),
    monitor_events (0),
    thread_safe (thread_safe_),
    reaper_signaler (NULL),
    sync(),
    monitor_sync()
{
    options.socket_id = sid_;
    options.ipv6 = (parent_->get (ZMQ_IPV6) != 0);
    options.linger = parent_->get (ZMQ_BLOCKY)? -1: 0;

    if (thread_safe)
    {
        mailbox = new (std::nothrow) mailbox_safe_t(&sync);
        zmq_assert (mailbox);
    }
    else {
        mailbox_t *m = new (std::nothrow) mailbox_t();
        zmq_assert (m);

        if (m->get_fd () != retired_fd)
            mailbox = m;
        else {
            LIBZMQ_DELETE (m);
            mailbox = NULL;
        }
    }
}

zmq::socket_base_t::~socket_base_t ()
{
    if (mailbox)
        LIBZMQ_DELETE(mailbox);

    if (reaper_signaler)
        LIBZMQ_DELETE(reaper_signaler);

    scoped_lock_t lock(monitor_sync);
    stop_monitor ();

    zmq_assert (destroyed);
}

zmq::i_mailbox *zmq::socket_base_t::get_mailbox ()
{
    return mailbox;
}

void zmq::socket_base_t::stop ()
{
    //  Called by ctx when it is terminated (zmq_ctx_term).
    //  'stop' command is sent from the threads that called zmq_ctx_term to
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
    //  First check out whether the protocol is something we are aware of.
    if (protocol_ != "inproc"
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    &&  protocol_ != "ipc"
#endif
    &&  protocol_ != "tcp"
#if defined ZMQ_HAVE_OPENPGM
    //  pgm/epgm transports only available if 0MQ is compiled with OpenPGM.
    &&  protocol_ != "pgm"
    &&  protocol_ != "epgm"
#endif
#if defined ZMQ_HAVE_TIPC
    // TIPC transport is only available on Linux.
    &&  protocol_ != "tipc"
#endif
#if defined ZMQ_HAVE_NORM
    &&  protocol_ != "norm"
#endif
#if defined ZMQ_HAVE_VMCI
    &&  protocol_ != "vmci"
#endif
    &&  protocol_ != "udp") {
        errno = EPROTONOSUPPORT;
        return -1;
    }

    //  Check whether socket type and transport protocol match.
    //  Specifically, multicast protocols can't be combined with
    //  bi-directional messaging patterns (socket types).
#if defined ZMQ_HAVE_OPENPGM || defined ZMQ_HAVE_NORM
    if ((protocol_ == "pgm" || protocol_ == "epgm" || protocol_ == "norm") &&
          options.type != ZMQ_PUB && options.type != ZMQ_SUB &&
          options.type != ZMQ_XPUB && options.type != ZMQ_XSUB) {
        errno = ENOCOMPATPROTO;
        return -1;
    }
#endif

    if (protocol_ == "udp" && (options.type != ZMQ_DISH &&
                               options.type != ZMQ_RADIO &&
                               options.type != ZMQ_DGRAM)) {
        errno = ENOCOMPATPROTO;
        return -1;
    }

    //  Protocol is available.
    return 0;
}

void zmq::socket_base_t::attach_pipe (pipe_t *pipe_, bool subscribe_to_all_)
{
    //  First, register the pipe so that we can terminate it later on.
    pipe_->set_event_sink (this);
    pipes.push_back (pipe_);

    //  Let the derived socket type know about new pipe.
    xattach_pipe (pipe_, subscribe_to_all_);

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
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (!options.is_valid(option_)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  First, check whether specific socket type overloads the option.
    int rc = xsetsockopt (option_, optval_, optvallen_);
    if (rc == 0 || errno != EINVAL) {
        return rc;
    }

    //  If the socket type doesn't support the option, pass it to
    //  the generic option parser.
    rc = options.setsockopt (option_, optval_, optvallen_);
    update_pipe_options(option_);

    return rc;
}

int zmq::socket_base_t::getsockopt (int option_, void *optval_,
    size_t *optvallen_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    if (option_ == ZMQ_RCVMORE) {
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        memset(optval_, 0, *optvallen_);
        *((int*) optval_) = rcvmore ? 1 : 0;
        *optvallen_ = sizeof (int);
        return 0;
    }

    if (option_ == ZMQ_FD) {
        if (*optvallen_ < sizeof (fd_t)) {
            errno = EINVAL;
            return -1;
        }

        if (thread_safe) {
            // thread safe socket doesn't provide file descriptor
            errno = EINVAL;
            return -1;
        }

        *((fd_t*)optval_) = ((mailbox_t*)mailbox)->get_fd();
        *optvallen_ = sizeof(fd_t);

        return 0;
    }

    if (option_ == ZMQ_EVENTS) {
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        int rc = process_commands (0, false);
        if (rc != 0 && (errno == EINTR || errno == ETERM)) {
            return -1;
        }
        errno_assert (rc == 0);
        *((int*) optval_) = 0;
        if (has_out ())
            *((int*) optval_) |= ZMQ_POLLOUT;
        if (has_in ())
            *((int*) optval_) |= ZMQ_POLLIN;
        *optvallen_ = sizeof (int);
        return 0;
    }

    if (option_ == ZMQ_LAST_ENDPOINT) {
        if (*optvallen_ < last_endpoint.size () + 1) {
            errno = EINVAL;
            return -1;
        }
        strncpy(static_cast <char *> (optval_), last_endpoint.c_str(), last_endpoint.size() + 1);
        *optvallen_ = last_endpoint.size () + 1;
        return 0;
    }

    if (option_ == ZMQ_THREAD_SAFE) {
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        memset(optval_, 0, *optvallen_);
        *((int*) optval_) = thread_safe ? 1 : 0;
        *optvallen_ = sizeof (int);
        return 0;
    }

    int rc = options.getsockopt (option_, optval_, optvallen_);
    return rc;
}

int zmq::socket_base_t::join (const char* group_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    int rc = xjoin (group_);


    return rc;
}

int zmq::socket_base_t::leave (const char* group_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    int rc = xleave (group_);


    return rc;
}

int zmq::socket_base_t::add_signaler(signaler_t *s_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (!thread_safe) {
        errno = EINVAL;
        return -1;
    }

    ((mailbox_safe_t*)mailbox)->add_signaler(s_);

    return 0;
}

int zmq::socket_base_t::remove_signaler(signaler_t *s_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (!thread_safe) {
        errno = EINVAL;
        return -1;
    }

    ((mailbox_safe_t*)mailbox)->remove_signaler(s_);

    return 0;
}

int zmq::socket_base_t::bind (const char *addr_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Process pending commands, if any.
    int rc = process_commands (0, false);
    if (unlikely (rc != 0)) {
        return -1;
    }

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    if (parse_uri (addr_, protocol, address) || check_protocol (protocol)) {
        return -1;
    }

    if (protocol == "inproc") {
        const endpoint_t endpoint = { this, options };
        rc = register_endpoint (addr_, endpoint);
        if (rc == 0) {
            connect_pending (addr_, this);
            last_endpoint.assign (addr_);
            options.connected = true;
        }
        return rc;
    }

    if (protocol == "pgm" || protocol == "epgm" || protocol == "norm") {
        //  For convenience's sake, bind can be used interchangeable with
        //  connect for PGM, EPGM, NORM transports.
        rc = connect (addr_);
        if (rc != -1)
            options.connected = true;
        return rc;
    }

    if (protocol == "udp") {
        if (!(options.type == ZMQ_DGRAM || options.type == ZMQ_DISH)) {
            errno = ENOCOMPATPROTO;
            return -1;
        }

        //  Choose the I/O thread to run the session in.
        io_thread_t *io_thread = choose_io_thread (options.affinity);
        if (!io_thread) {
            errno = EMTHREAD;
            return -1;
        }

        address_t *paddr = new (std::nothrow) address_t (protocol, address, this->get_ctx ());
        alloc_assert (paddr);

        paddr->resolved.udp_addr = new (std::nothrow) udp_address_t ();
        alloc_assert (paddr->resolved.udp_addr);
        rc = paddr->resolved.udp_addr->resolve (address.c_str(), true);
        if (rc != 0) {
            LIBZMQ_DELETE(paddr);
            return -1;
        }

        session_base_t *session = session_base_t::create (io_thread, true, this,
            options, paddr);
        errno_assert (session);

        pipe_t *newpipe = NULL;

        //  Create a bi-directional pipe.
        object_t *parents [2] = {this, session};
        pipe_t *new_pipes [2] = {NULL, NULL};

        int hwms [2] = {options.sndhwm, options.rcvhwm};
        bool conflates [2] = {false, false};
        rc = pipepair (parents, new_pipes, hwms, conflates);
        errno_assert (rc == 0);

        //  Attach local end of the pipe to the socket object.
        attach_pipe (new_pipes [0], true);
        newpipe = new_pipes [0];

        //  Attach remote end of the pipe to the session object later on.
        session->attach_pipe (new_pipes [1]);

        //  Save last endpoint URI
        paddr->to_string (last_endpoint);

        add_endpoint (addr_, (own_t *) session, newpipe);

        return 0;
    }

    //  Remaining transports require to be run in an I/O thread, so at this
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
        rc = listener->set_address (address.c_str ());
        if (rc != 0) {
            LIBZMQ_DELETE(listener);
            event_bind_failed (address, zmq_errno());
            return -1;
        }

        // Save last endpoint URI
        listener->get_address (last_endpoint);

        add_endpoint (last_endpoint.c_str (), (own_t *) listener, NULL);
        options.connected = true;
        return 0;
    }

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    if (protocol == "ipc") {
        ipc_listener_t *listener = new (std::nothrow) ipc_listener_t (
            io_thread, this, options);
        alloc_assert (listener);
        int rc = listener->set_address (address.c_str ());
        if (rc != 0) {
            LIBZMQ_DELETE(listener);
            event_bind_failed (address, zmq_errno());
            return -1;
        }

        // Save last endpoint URI
        listener->get_address (last_endpoint);

        add_endpoint (last_endpoint.c_str (), (own_t *) listener, NULL);
        options.connected = true;
        return 0;
    }
#endif
#if defined ZMQ_HAVE_TIPC
    if (protocol == "tipc") {
         tipc_listener_t *listener = new (std::nothrow) tipc_listener_t (
              io_thread, this, options);
         alloc_assert (listener);
         int rc = listener->set_address (address.c_str ());
         if (rc != 0) {
             LIBZMQ_DELETE(listener);
             event_bind_failed (address, zmq_errno());
             return -1;
         }

        // Save last endpoint URI
        listener->get_address (last_endpoint);

        add_endpoint (addr_, (own_t *) listener, NULL);
        options.connected = true;
        return 0;
    }
#endif
#if defined ZMQ_HAVE_VMCI
    if (protocol == "vmci") {
        vmci_listener_t *listener = new (std::nothrow) vmci_listener_t (
            io_thread, this, options);
        alloc_assert (listener);
        int rc = listener->set_address (address.c_str ());
        if (rc != 0) {
            LIBZMQ_DELETE(listener);
            event_bind_failed (address, zmq_errno ());
            return -1;
        }

        listener->get_address (last_endpoint);

        add_endpoint (last_endpoint.c_str(), (own_t *) listener, NULL);
        options.connected = true;
        return 0;
    }
#endif

    zmq_assert (false);
    return -1;
}

int zmq::socket_base_t::connect (const char *addr_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Process pending commands, if any.
    int rc = process_commands (0, false);
    if (unlikely (rc != 0)) {
        return -1;
    }

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    if (parse_uri (addr_, protocol, address) || check_protocol (protocol)) {
        return -1;
    }

    if (protocol == "inproc") {

        //  TODO: inproc connect is specific with respect to creating pipes
        //  as there's no 'reconnect' functionality implemented. Once that
        //  is in place we should follow generic pipe creation algorithm.

        //  Find the peer endpoint.
        endpoint_t peer = find_endpoint (addr_);

        // The total HWM for an inproc connection should be the sum of
        // the binder's HWM and the connector's HWM.
        int sndhwm = 0;
        if (peer.socket == NULL)
            sndhwm = options.sndhwm;
        else if (options.sndhwm != 0 && peer.options.rcvhwm != 0)
            sndhwm = options.sndhwm + peer.options.rcvhwm;
        int rcvhwm = 0;
        if (peer.socket == NULL)
            rcvhwm = options.rcvhwm;
        else
        if (options.rcvhwm != 0 && peer.options.sndhwm != 0)
            rcvhwm = options.rcvhwm + peer.options.sndhwm;

        //  Create a bi-directional pipe to connect the peers.
        object_t *parents [2] = {this, peer.socket == NULL ? this : peer.socket};
        pipe_t *new_pipes [2] = {NULL, NULL};

        bool conflate = options.conflate &&
            (options.type == ZMQ_DEALER ||
             options.type == ZMQ_PULL ||
             options.type == ZMQ_PUSH ||
             options.type == ZMQ_PUB ||
             options.type == ZMQ_SUB);

        int hwms [2] = {conflate? -1 : sndhwm, conflate? -1 : rcvhwm};
        bool conflates [2] = {conflate, conflate};
        rc = pipepair (parents, new_pipes, hwms, conflates);
        if (!conflate) {
            new_pipes[0]->set_hwms_boost(peer.options.sndhwm, peer.options.rcvhwm);
            new_pipes[1]->set_hwms_boost(options.sndhwm, options.rcvhwm);
        }

        errno_assert (rc == 0);

        if (!peer.socket) {
            //  The peer doesn't exist yet so we don't know whether
            //  to send the identity message or not. To resolve this,
            //  we always send our identity and drop it later if
            //  the peer doesn't expect it.
            msg_t id;
            rc = id.init_size (options.identity_size);
            errno_assert (rc == 0);
            memcpy (id.data (), options.identity, options.identity_size);
            id.set_flags (msg_t::identity);
            bool written = new_pipes [0]->write (&id);
            zmq_assert (written);
            new_pipes [0]->flush ();

            const endpoint_t endpoint = {this, options};
            pend_connection (std::string (addr_), endpoint, new_pipes);
        }
        else {
            //  If required, send the identity of the local socket to the peer.
            if (peer.options.recv_identity) {
                msg_t id;
                rc = id.init_size (options.identity_size);
                errno_assert (rc == 0);
                memcpy (id.data (), options.identity, options.identity_size);
                id.set_flags (msg_t::identity);
                bool written = new_pipes [0]->write (&id);
                zmq_assert (written);
                new_pipes [0]->flush ();
            }

            //  If required, send the identity of the peer to the local socket.
            if (options.recv_identity) {
                msg_t id;
                rc = id.init_size (peer.options.identity_size);
                errno_assert (rc == 0);
                memcpy (id.data (), peer.options.identity, peer.options.identity_size);
                id.set_flags (msg_t::identity);
                bool written = new_pipes [1]->write (&id);
                zmq_assert (written);
                new_pipes [1]->flush ();
            }

            //  Attach remote end of the pipe to the peer socket. Note that peer's
            //  seqnum was incremented in find_endpoint function. We don't need it
            //  increased here.
            send_bind (peer.socket, new_pipes [1], false);
        }

        //  Attach local end of the pipe to this socket object.
        attach_pipe (new_pipes [0]);

        // Save last endpoint URI
        last_endpoint.assign (addr_);

        // remember inproc connections for disconnect
        inprocs.insert (inprocs_t::value_type (std::string (addr_), new_pipes [0]));

        options.connected = true;
        return 0;
    }
    bool is_single_connect = (options.type == ZMQ_DEALER ||
                              options.type == ZMQ_SUB ||
                              options.type == ZMQ_REQ);
    if (unlikely (is_single_connect)) {
        const endpoints_t::iterator it = endpoints.find (addr_);
        if (it != endpoints.end ()) {
            // There is no valid use for multiple connects for SUB-PUB nor
            // DEALER-ROUTER nor REQ-REP. Multiple connects produces
            // nonsensical results.
            return 0;
        }
    }

    //  Choose the I/O thread to run the session in.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    if (!io_thread) {
        errno = EMTHREAD;
        return -1;
    }

    address_t *paddr = new (std::nothrow) address_t (protocol, address, this->get_ctx ());
    alloc_assert (paddr);

    //  Resolve address (if needed by the protocol)
    if (protocol == "tcp") {
        //  Do some basic sanity checks on tcp:// address syntax
        //  - hostname starts with digit or letter, with embedded '-' or '.'
        //  - IPv6 address may contain hex chars and colons.
        //  - IPv6 link local address may contain % followed by interface name / zone_id
        //    (Reference: https://tools.ietf.org/html/rfc4007)
        //  - IPv4 address may contain decimal digits and dots.
        //  - Address must end in ":port" where port is *, or numeric
        //  - Address may contain two parts separated by ':'
        //  Following code is quick and dirty check to catch obvious errors,
        //  without trying to be fully accurate.
        const char *check = address.c_str ();
        if (isalnum (*check) || isxdigit (*check) || *check == '[' || *check == ':') {
            check++;
            while (isalnum  (*check)
                || isxdigit (*check)
                || *check == '.' || *check == '-' || *check == ':' || *check == '%'
                || *check == ';' || *check == '['  || *check == ']' || *check == '_'
            ) {
                check++;
            }
        }
        //  Assume the worst, now look for success
        rc = -1;
        //  Did we reach the end of the address safely?
        if (*check == 0) {
            //  Do we have a valid port string? (cannot be '*' in connect
            check = strrchr (address.c_str (), ':');
            if (check) {
                check++;
                if (*check && (isdigit (*check)))
                    rc = 0;     //  Valid
            }
        }
        if (rc == -1) {
            errno = EINVAL;
            LIBZMQ_DELETE(paddr);
            return -1;
        }
        //  Defer resolution until a socket is opened
        paddr->resolved.tcp_addr = NULL;
    }
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS
    else
    if (protocol == "ipc") {
        paddr->resolved.ipc_addr = new (std::nothrow) ipc_address_t ();
        alloc_assert (paddr->resolved.ipc_addr);
        int rc = paddr->resolved.ipc_addr->resolve (address.c_str ());
        if (rc != 0) {
            LIBZMQ_DELETE(paddr);
            return -1;
        }
    }
#endif

if (protocol  == "udp") {
    if (options.type != ZMQ_RADIO) {
        errno = ENOCOMPATPROTO;
        LIBZMQ_DELETE(paddr);
        return -1;
    }

    paddr->resolved.udp_addr = new (std::nothrow) udp_address_t ();
    alloc_assert (paddr->resolved.udp_addr);
    rc = paddr->resolved.udp_addr->resolve (address.c_str(), false);
    if (rc != 0) {
        LIBZMQ_DELETE(paddr);
        return -1;
    }
}

// TBD - Should we check address for ZMQ_HAVE_NORM???

#ifdef ZMQ_HAVE_OPENPGM
    if (protocol == "pgm" || protocol == "epgm") {
        struct pgm_addrinfo_t *res = NULL;
        uint16_t port_number = 0;
        int rc = pgm_socket_t::init_address(address.c_str(), &res, &port_number);
        if (res != NULL)
            pgm_freeaddrinfo (res);
        if (rc != 0 || port_number == 0) {
          return -1;
        }
    }
#endif
#if defined ZMQ_HAVE_TIPC
    else
    if (protocol == "tipc") {
        paddr->resolved.tipc_addr = new (std::nothrow) tipc_address_t ();
        alloc_assert (paddr->resolved.tipc_addr);
        int rc = paddr->resolved.tipc_addr->resolve (address.c_str());
        if (rc != 0) {
            LIBZMQ_DELETE(paddr);
            return -1;
        }
    }
#endif
#if defined ZMQ_HAVE_VMCI
    else
    if (protocol == "vmci") {
        paddr->resolved.vmci_addr = new (std::nothrow) vmci_address_t (this->get_ctx ());
        alloc_assert (paddr->resolved.vmci_addr);
        int rc = paddr->resolved.vmci_addr->resolve (address.c_str ());
        if (rc != 0) {
            LIBZMQ_DELETE(paddr);
            return -1;
        }
    }
#endif

    //  Create session.
    session_base_t *session = session_base_t::create (io_thread, true, this,
        options, paddr);
    errno_assert (session);

    //  PGM does not support subscription forwarding; ask for all data to be
    //  sent to this pipe. (same for NORM, currently?)
    bool subscribe_to_all = protocol == "pgm" || protocol == "epgm" || protocol == "norm" || protocol == "udp";
    pipe_t *newpipe = NULL;

    if (options.immediate != 1 || subscribe_to_all) {
        //  Create a bi-directional pipe.
        object_t *parents [2] = {this, session};
        pipe_t *new_pipes [2] = {NULL, NULL};

        bool conflate = options.conflate &&
            (options.type == ZMQ_DEALER ||
             options.type == ZMQ_PULL ||
             options.type == ZMQ_PUSH ||
             options.type == ZMQ_PUB ||
             options.type == ZMQ_SUB);

        int hwms [2] = {conflate? -1 : options.sndhwm,
            conflate? -1 : options.rcvhwm};
        bool conflates [2] = {conflate, conflate};
        rc = pipepair (parents, new_pipes, hwms, conflates);
        errno_assert (rc == 0);

        //  Attach local end of the pipe to the socket object.
        attach_pipe (new_pipes [0], subscribe_to_all);
        newpipe = new_pipes [0];

        //  Attach remote end of the pipe to the session object later on.
        session->attach_pipe (new_pipes [1]);
    }

    //  Save last endpoint URI
    paddr->to_string (last_endpoint);

    add_endpoint (addr_, (own_t *) session, newpipe);
    return 0;
}

void zmq::socket_base_t::add_endpoint (const char *addr_, own_t *endpoint_, pipe_t *pipe)
{
    //  Activate the session. Make it a child of this socket.
    launch_child (endpoint_);
    endpoints.insert (endpoints_t::value_type (std::string (addr_), endpoint_pipe_t (endpoint_, pipe)));
}

int zmq::socket_base_t::term_endpoint (const char *addr_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

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
    if (unlikely(rc != 0)) {
        return -1;
    }

    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    if (parse_uri(addr_, protocol, address) || check_protocol(protocol)) {
        return -1;
    }

    // Disconnect an inproc socket
    if (protocol == "inproc") {
        if (unregister_endpoint (std::string(addr_), this) == 0) {
            return 0;
        }
        std::pair <inprocs_t::iterator, inprocs_t::iterator> range = inprocs.equal_range (std::string (addr_));
        if (range.first == range.second) {
            errno = ENOENT;
            return -1;
        }

        for (inprocs_t::iterator it = range.first; it != range.second; ++it)
            it->second->terminate (true);
        inprocs.erase (range.first, range.second);
        return 0;
    }

    std::string resolved_addr = std::string (addr_);
    std::pair <endpoints_t::iterator, endpoints_t::iterator> range;

    // The resolved last_endpoint is used as a key in the endpoints map.
    // The address passed by the user might not match in the TCP case due to
    // IPv4-in-IPv6 mapping (EG: tcp://[::ffff:127.0.0.1]:9999), so try to
    // resolve before giving up. Given at this stage we don't know whether a
    // socket is connected or bound, try with both.
    if (protocol == "tcp") {
        range = endpoints.equal_range (resolved_addr);
        if (range.first == range.second) {
            tcp_address_t *tcp_addr = new (std::nothrow) tcp_address_t ();
            alloc_assert (tcp_addr);
            rc = tcp_addr->resolve (address.c_str (), false, options.ipv6);

            if (rc == 0) {
                tcp_addr->to_string (resolved_addr);
                range = endpoints.equal_range (resolved_addr);

                if (range.first == range.second) {
                    rc = tcp_addr->resolve (address.c_str (), true, options.ipv6);
                    if (rc == 0) {
                        tcp_addr->to_string (resolved_addr);
                    }
                }
            }
            LIBZMQ_DELETE(tcp_addr);
        }
    }

    //  Find the endpoints range (if any) corresponding to the addr_ string.
    range = endpoints.equal_range (resolved_addr);
    if (range.first == range.second) {
        errno = ENOENT;
        return -1;
    }

    for (endpoints_t::iterator it = range.first; it != range.second; ++it) {
        //  If we have an associated pipe, terminate it.
        if (it->second.second != NULL)
            it->second.second->terminate (false);
        term_child (it->second.first);
    }
    endpoints.erase (range.first, range.second);
    return 0;
}

int zmq::socket_base_t::send (msg_t *msg_, int flags_)
{
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

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
    if (unlikely (rc != 0)) {
        return -1;
    }

    //  Clear any user-visible flags that are set on the message.
    msg_->reset_flags (msg_t::more);

    //  At this point we impose the flags on the message.
    if (flags_ & ZMQ_SNDMORE)
        msg_->set_flags (msg_t::more);

    msg_->reset_metadata ();

    //  Try to send the message using method in each socket class
    rc = xsend (msg_);
    if (rc == 0) {
        return 0;
    }
    if (unlikely (errno != EAGAIN)) {
        return -1;
    }

    //  In case of non-blocking send we'll simply propagate
    //  the error - including EAGAIN - up the stack.
    if (flags_ & ZMQ_DONTWAIT || options.sndtimeo == 0) {
        return -1;
    }

    //  Compute the time when the timeout should occur.
    //  If the timeout is infinite, don't care.
    int timeout = options.sndtimeo;
    uint64_t end = timeout < 0 ? 0 : (clock.now_ms () + timeout);

    //  Oops, we couldn't send the message. Wait for the next
    //  command, process it and try to send the message again.
    //  If timeout is reached in the meantime, return EAGAIN.
    while (true) {
        if (unlikely (process_commands (timeout, false) != 0)) {
            return -1;
        }
        rc = xsend (msg_);
        if (rc == 0)
            break;
        if (unlikely (errno != EAGAIN)) {
            return -1;
        }
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
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

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
        if (unlikely (process_commands (0, false) != 0)) {
            return -1;
        }
        ticks = 0;
    }

    //  Get the message.
    int rc = xrecv (msg_);
    if (unlikely (rc != 0 && errno != EAGAIN)) {
        return -1;
    }

    //  If we have the message, return immediately.
    if (rc == 0) {
        extract_flags (msg_);
        return 0;
    }

    //  If the message cannot be fetched immediately, there are two scenarios.
    //  For non-blocking recv, commands are processed in case there's an
    //  activate_reader command already waiting in a command pipe.
    //  If it's not, return EAGAIN.
    if (flags_ & ZMQ_DONTWAIT || options.rcvtimeo == 0) {
        if (unlikely (process_commands (0, false) != 0)) {
            return -1;
        }
        ticks = 0;

        rc = xrecv (msg_);
        if (rc < 0) {
            return rc;
        }
        extract_flags (msg_);

        return 0;
    }

    //  Compute the time when the timeout should occur.
    //  If the timeout is infinite, don't care.
    int timeout = options.rcvtimeo;
    uint64_t end = timeout < 0 ? 0 : (clock.now_ms () + timeout);

    //  In blocking scenario, commands are processed over and over again until
    //  we are able to fetch a message.
    bool block = (ticks != 0);
    while (true) {
        if (unlikely (process_commands (block ? timeout : 0, false) != 0)) {
            return -1;
        }
        rc = xrecv (msg_);
        if (rc == 0) {
            ticks = 0;
            break;
        }
        if (unlikely (errno != EAGAIN)) {
            return -1;
        }
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
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    //  Remove all existing signalers for thread safe sockets
    if (thread_safe)
        ((mailbox_safe_t*)mailbox)->clear_signalers();

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

    fd_t fd;

    if (!thread_safe)
        fd = ((mailbox_t*)mailbox)->get_fd();
    else {
        scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

        reaper_signaler = new (std::nothrow) signaler_t();
        zmq_assert (reaper_signaler);

        //  Add signaler to the safe mailbox
        fd = reaper_signaler->get_fd();
        ((mailbox_safe_t*)mailbox)->add_signaler(reaper_signaler);

        //  Send a signal to make sure reaper handle existing commands
        reaper_signaler->send();

    }

    handle = poller->add_fd (fd, this);
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
        rc = mailbox->recv (&cmd, timeout_);
    }
    else {

        //  If we are asked not to wait, check whether we haven't processed
        //  commands recently, so that we can throttle the new commands.

        //  Get the CPU's tick counter. If 0, the counter is not available.
        const uint64_t tsc = zmq::clock_t::rdtsc ();

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
        rc = mailbox->recv (&cmd, 0);
    }

    //  Process all available commands.
    while (rc == 0) {
        cmd.destination->process_command (cmd);
        rc = mailbox->recv (&cmd, 0);
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
    //  Here, someone have called zmq_ctx_term while the socket was still alive.
    //  We'll remember the fact so that any blocking call is interrupted and any
    //  further attempt to use the socket will return ETERM. The user is still
    //  responsible for calling zmq_close on the socket though!
    scoped_lock_t lock(monitor_sync);
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

void zmq::socket_base_t::update_pipe_options(int option_)
{
    if (option_ == ZMQ_SNDHWM || option_ == ZMQ_RCVHWM)
    {
        for (pipes_t::size_type i = 0; i != pipes.size(); ++i)
        {
            pipes[i]->set_hwms(options.rcvhwm, options.sndhwm);
            pipes[i]->send_hwms_to_peer(options.sndhwm, options.rcvhwm);
        }
    }

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

int zmq::socket_base_t::xsend (msg_t *)
{
    errno = ENOTSUP;
    return -1;
}

bool zmq::socket_base_t::xhas_in ()
{
    return false;
}

int zmq::socket_base_t::xjoin (const char *group_)
{
    LIBZMQ_UNUSED (group_);
    errno = ENOTSUP;
    return -1;
}

int zmq::socket_base_t::xleave (const char *group_)
{
    LIBZMQ_UNUSED (group_);
    errno = ENOTSUP;
    return -1;
}

int zmq::socket_base_t::xrecv (msg_t *)
{
    errno = ENOTSUP;
    return -1;
}

zmq::blob_t zmq::socket_base_t::get_credential () const
{
    return blob_t ();
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
  {
    scoped_optional_lock_t sync_lock(thread_safe ? &sync : NULL);

    //  If the socket is thread safe we need to unsignal the reaper signaler
    if (thread_safe)
        reaper_signaler->recv();

    process_commands (0, false);
  }
    check_destroy();
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
    if (options.immediate == 1)
        pipe_->terminate (false);
    else
        // Notify derived sockets of the hiccup
        xhiccuped (pipe_);
}

void zmq::socket_base_t::pipe_terminated (pipe_t *pipe_)
{
    //  Notify the specific socket type about the pipe termination.
    xpipe_terminated (pipe_);

    // Remove pipe from inproc pipes
    for (inprocs_t::iterator it = inprocs.begin (); it != inprocs.end (); ++it)
        if (it->second == pipe_) {
            inprocs.erase (it);
            break;
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
    scoped_lock_t lock(monitor_sync);
    
    if (unlikely (ctx_terminated)) {
        errno = ETERM;
        return -1;
    }

    //  Support deregistering monitoring endpoints as well
    if (addr_ == NULL) {
        stop_monitor ();
        return 0;
    }
    //  Parse addr_ string.
    std::string protocol;
    std::string address;
    if (parse_uri (addr_, protocol, address) || check_protocol (protocol))
        return -1;

    //  Event notification only supported over inproc://
    if (protocol != "inproc") {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    // already monitoring. Stop previous monitor before starting new one.
    if (monitor_socket != NULL) {
        stop_monitor (true);
    }
    //  Register events to monitor
    monitor_events = events_;
    monitor_socket = zmq_socket (get_ctx (), ZMQ_PAIR);
    if (monitor_socket == NULL)
        return -1;

    //  Never block context termination on pending event messages
    int linger = 0;
    int rc = zmq_setsockopt (monitor_socket, ZMQ_LINGER, &linger, sizeof (linger));
    if (rc == -1)
        stop_monitor (false);

    //  Spawn the monitor socket endpoint
    rc = zmq_bind (monitor_socket, addr_);
    if (rc == -1)
         stop_monitor (false);
    return rc;
}

void zmq::socket_base_t::event_connected (const std::string &addr_, zmq::fd_t fd_)
{
    event(addr_, fd_, ZMQ_EVENT_CONNECTED);
}

void zmq::socket_base_t::event_connect_delayed (const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_CONNECT_DELAYED);
}

void zmq::socket_base_t::event_connect_retried (const std::string &addr_, int interval_)
{
    event(addr_, interval_, ZMQ_EVENT_CONNECT_RETRIED);
}

void zmq::socket_base_t::event_listening (const std::string &addr_, zmq::fd_t fd_)
{
    event(addr_, fd_, ZMQ_EVENT_LISTENING);
}

void zmq::socket_base_t::event_bind_failed (const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_BIND_FAILED);
}

void zmq::socket_base_t::event_accepted (const std::string &addr_, zmq::fd_t fd_)
{
    event(addr_, fd_, ZMQ_EVENT_ACCEPTED);
}

void zmq::socket_base_t::event_accept_failed (const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_ACCEPT_FAILED);
}

void zmq::socket_base_t::event_closed (const std::string &addr_, zmq::fd_t fd_)
{
    event(addr_, fd_, ZMQ_EVENT_CLOSED);
}

void zmq::socket_base_t::event_close_failed (const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_CLOSE_FAILED);
}

void zmq::socket_base_t::event_disconnected (const std::string &addr_, zmq::fd_t fd_)
{
    event(addr_, fd_, ZMQ_EVENT_DISCONNECTED);
}

void zmq::socket_base_t::event_handshake_failed(const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_HANDSHAKE_FAILED);
}

void zmq::socket_base_t::event_handshake_succeed(const std::string &addr_, int err_)
{
    event(addr_, err_, ZMQ_EVENT_HANDSHAKE_SUCCEED);
}

void zmq::socket_base_t::event(const std::string &addr_, intptr_t value_, int type_)
{
    scoped_lock_t lock(monitor_sync);
    if (monitor_events & type_)
    {
        monitor_event (type_, value_, addr_);
    }
}

//  Send a monitor event
void zmq::socket_base_t::monitor_event (int event_, intptr_t value_, const std::string &addr_)
{
    // this is a private method which is only called from
    // contexts where the mutex has been locked before

    if (monitor_socket) {
        //  Send event in first frame
        zmq_msg_t msg;
        zmq_msg_init_size (&msg, 6);
        uint8_t *data = (uint8_t *) zmq_msg_data (&msg);
        //  Avoid dereferencing uint32_t on unaligned address
        uint16_t event = (uint16_t) event_;
        uint32_t value = (uint32_t) value_;
        memcpy (data + 0, &event, sizeof(event));
        memcpy (data + 2, &value, sizeof(value));
        zmq_sendmsg (monitor_socket, &msg, ZMQ_SNDMORE);

        //  Send address in second frame
        zmq_msg_init_size (&msg, addr_.size());
        memcpy (zmq_msg_data (&msg), addr_.c_str (), addr_.size ());
        zmq_sendmsg (monitor_socket, &msg, 0);
    }
}

void zmq::socket_base_t::stop_monitor (bool send_monitor_stopped_event_)
{
    // this is a private method which is only called from
    // contexts where the mutex has been locked before

    if (monitor_socket) {
        if ((monitor_events & ZMQ_EVENT_MONITOR_STOPPED) && send_monitor_stopped_event_)
            monitor_event (ZMQ_EVENT_MONITOR_STOPPED, 0, "");
        zmq_close (monitor_socket);
        monitor_socket = NULL;
        monitor_events = 0;
    }
}
