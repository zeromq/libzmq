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
#include "macros.hpp"
#include "session_base.hpp"
#include "i_engine.hpp"
#include "err.hpp"
#include "pipe.hpp"
#include "likely.hpp"
#include "tcp_connecter.hpp"
#include "ws_connecter.hpp"
#include "ipc_connecter.hpp"
#include "tipc_connecter.hpp"
#include "socks_connecter.hpp"
#include "vmci_connecter.hpp"
#include "pgm_sender.hpp"
#include "pgm_receiver.hpp"
#include "address.hpp"
#include "norm_engine.hpp"
#include "udp_engine.hpp"

#include "ctx.hpp"
#include "req.hpp"
#include "radio.hpp"
#include "dish.hpp"

zmq::session_base_t *zmq::session_base_t::create (class io_thread_t *io_thread_,
                                                  bool active_,
                                                  class socket_base_t *socket_,
                                                  const options_t &options_,
                                                  address_t *addr_)
{
    session_base_t *s = NULL;
    switch (options_.type) {
        case ZMQ_REQ:
            s = new (std::nothrow)
              req_session_t (io_thread_, active_, socket_, options_, addr_);
            break;
        case ZMQ_RADIO:
            s = new (std::nothrow)
              radio_session_t (io_thread_, active_, socket_, options_, addr_);
            break;
        case ZMQ_DISH:
            s = new (std::nothrow)
              dish_session_t (io_thread_, active_, socket_, options_, addr_);
            break;
        case ZMQ_DEALER:
        case ZMQ_REP:
        case ZMQ_ROUTER:
        case ZMQ_PUB:
        case ZMQ_XPUB:
        case ZMQ_SUB:
        case ZMQ_XSUB:
        case ZMQ_PUSH:
        case ZMQ_PULL:
        case ZMQ_PAIR:
        case ZMQ_STREAM:
        case ZMQ_SERVER:
        case ZMQ_CLIENT:
        case ZMQ_GATHER:
        case ZMQ_SCATTER:
        case ZMQ_DGRAM:
            s = new (std::nothrow)
              session_base_t (io_thread_, active_, socket_, options_, addr_);
            break;
        default:
            errno = EINVAL;
            return NULL;
    }
    alloc_assert (s);
    return s;
}

zmq::session_base_t::session_base_t (class io_thread_t *io_thread_,
                                     bool active_,
                                     class socket_base_t *socket_,
                                     const options_t &options_,
                                     address_t *addr_) :
    own_t (io_thread_, options_),
    io_object_t (io_thread_),
    _active (active_),
    _pipe (NULL),
    _zap_pipe (NULL),
    _incomplete_in (false),
    _pending (false),
    _engine (NULL),
    _socket (socket_),
    _io_thread (io_thread_),
    _has_linger_timer (false),
    _addr (addr_)
{
}

const zmq::endpoint_uri_pair_t &zmq::session_base_t::get_endpoint () const
{
    return _engine->get_endpoint ();
}

zmq::session_base_t::~session_base_t ()
{
    zmq_assert (!_pipe);
    zmq_assert (!_zap_pipe);

    //  If there's still a pending linger timer, remove it.
    if (_has_linger_timer) {
        cancel_timer (linger_timer_id);
        _has_linger_timer = false;
    }

    //  Close the engine.
    if (_engine)
        _engine->terminate ();

    LIBZMQ_DELETE (_addr);
}

void zmq::session_base_t::attach_pipe (pipe_t *pipe_)
{
    zmq_assert (!is_terminating ());
    zmq_assert (!_pipe);
    zmq_assert (pipe_);
    _pipe = pipe_;
    _pipe->set_event_sink (this);
}

int zmq::session_base_t::pull_msg (msg_t *msg_)
{
    if (!_pipe || !_pipe->read (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    _incomplete_in = (msg_->flags () & msg_t::more) != 0;

    return 0;
}

int zmq::session_base_t::push_msg (msg_t *msg_)
{
    //  pass subscribe/cancel to the sockets
    if ((msg_->flags () & msg_t::command) && !msg_->is_subscribe ()
        && !msg_->is_cancel ())
        return 0;
    if (_pipe && _pipe->write (msg_)) {
        int rc = msg_->init ();
        errno_assert (rc == 0);
        return 0;
    }

    errno = EAGAIN;
    return -1;
}

int zmq::session_base_t::read_zap_msg (msg_t *msg_)
{
    if (_zap_pipe == NULL) {
        errno = ENOTCONN;
        return -1;
    }

    if (!_zap_pipe->read (msg_)) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}

int zmq::session_base_t::write_zap_msg (msg_t *msg_)
{
    if (_zap_pipe == NULL || !_zap_pipe->write (msg_)) {
        errno = ENOTCONN;
        return -1;
    }

    if ((msg_->flags () & msg_t::more) == 0)
        _zap_pipe->flush ();

    const int rc = msg_->init ();
    errno_assert (rc == 0);
    return 0;
}

void zmq::session_base_t::reset ()
{
}

void zmq::session_base_t::flush ()
{
    if (_pipe)
        _pipe->flush ();
}

void zmq::session_base_t::rollback ()
{
    if (_pipe)
        _pipe->rollback ();
}

void zmq::session_base_t::clean_pipes ()
{
    zmq_assert (_pipe != NULL);

    //  Get rid of half-processed messages in the out pipe. Flush any
    //  unflushed messages upstream.
    _pipe->rollback ();
    _pipe->flush ();

    //  Remove any half-read message from the in pipe.
    while (_incomplete_in) {
        msg_t msg;
        int rc = msg.init ();
        errno_assert (rc == 0);
        rc = pull_msg (&msg);
        errno_assert (rc == 0);
        rc = msg.close ();
        errno_assert (rc == 0);
    }
}

void zmq::session_base_t::pipe_terminated (pipe_t *pipe_)
{
    // Drop the reference to the deallocated pipe if required.
    zmq_assert (pipe_ == _pipe || pipe_ == _zap_pipe
                || _terminating_pipes.count (pipe_) == 1);

    if (pipe_ == _pipe) {
        // If this is our current pipe, remove it
        _pipe = NULL;
        if (_has_linger_timer) {
            cancel_timer (linger_timer_id);
            _has_linger_timer = false;
        }
    } else if (pipe_ == _zap_pipe)
        _zap_pipe = NULL;
    else
        // Remove the pipe from the detached pipes set
        _terminating_pipes.erase (pipe_);

    if (!is_terminating () && options.raw_socket) {
        if (_engine) {
            _engine->terminate ();
            _engine = NULL;
        }
        terminate ();
    }

    //  If we are waiting for pending messages to be sent, at this point
    //  we are sure that there will be no more messages and we can proceed
    //  with termination safely.
    if (_pending && !_pipe && !_zap_pipe && _terminating_pipes.empty ()) {
        _pending = false;
        own_t::process_term (0);
    }
}

void zmq::session_base_t::read_activated (pipe_t *pipe_)
{
    // Skip activating if we're detaching this pipe
    if (unlikely (pipe_ != _pipe && pipe_ != _zap_pipe)) {
        zmq_assert (_terminating_pipes.count (pipe_) == 1);
        return;
    }

    if (unlikely (_engine == NULL)) {
        _pipe->check_read ();
        return;
    }

    if (likely (pipe_ == _pipe))
        _engine->restart_output ();
    else {
        // i.e. pipe_ == zap_pipe
        _engine->zap_msg_available ();
    }
}

void zmq::session_base_t::write_activated (pipe_t *pipe_)
{
    // Skip activating if we're detaching this pipe
    if (_pipe != pipe_) {
        zmq_assert (_terminating_pipes.count (pipe_) == 1);
        return;
    }

    if (_engine)
        _engine->restart_input ();
}

void zmq::session_base_t::hiccuped (pipe_t *)
{
    //  Hiccups are always sent from session to socket, not the other
    //  way round.
    zmq_assert (false);
}

zmq::socket_base_t *zmq::session_base_t::get_socket ()
{
    return _socket;
}

void zmq::session_base_t::process_plug ()
{
    if (_active)
        start_connecting (false);
}

//  This functions can return 0 on success or -1 and errno=ECONNREFUSED if ZAP
//  is not setup (IE: inproc://zeromq.zap.01 does not exist in the same context)
//  or it aborts on any other error. In other words, either ZAP is not
//  configured or if it is configured it MUST be configured correctly and it
//  MUST work, otherwise authentication cannot be guaranteed and it would be a
//  security flaw.
int zmq::session_base_t::zap_connect ()
{
    if (_zap_pipe != NULL)
        return 0;

    endpoint_t peer = find_endpoint ("inproc://zeromq.zap.01");
    if (peer.socket == NULL) {
        errno = ECONNREFUSED;
        return -1;
    }
    zmq_assert (peer.options.type == ZMQ_REP || peer.options.type == ZMQ_ROUTER
                || peer.options.type == ZMQ_SERVER);

    //  Create a bi-directional pipe that will connect
    //  session with zap socket.
    object_t *parents[2] = {this, peer.socket};
    pipe_t *new_pipes[2] = {NULL, NULL};
    int hwms[2] = {0, 0};
    bool conflates[2] = {false, false};
    int rc = pipepair (parents, new_pipes, hwms, conflates);
    errno_assert (rc == 0);

    //  Attach local end of the pipe to this socket object.
    _zap_pipe = new_pipes[0];
    _zap_pipe->set_nodelay ();
    _zap_pipe->set_event_sink (this);

    send_bind (peer.socket, new_pipes[1], false);

    //  Send empty routing id if required by the peer.
    if (peer.options.recv_routing_id) {
        msg_t id;
        rc = id.init ();
        errno_assert (rc == 0);
        id.set_flags (msg_t::routing_id);
        bool ok = _zap_pipe->write (&id);
        zmq_assert (ok);
        _zap_pipe->flush ();
    }

    return 0;
}

bool zmq::session_base_t::zap_enabled ()
{
    return (options.mechanism != ZMQ_NULL || !options.zap_domain.empty ());
}

void zmq::session_base_t::process_attach (i_engine *engine_)
{
    zmq_assert (engine_ != NULL);

    //  Create the pipe if it does not exist yet.
    if (!_pipe && !is_terminating ()) {
        object_t *parents[2] = {this, _socket};
        pipe_t *pipes[2] = {NULL, NULL};

        const bool conflate = get_effective_conflate_option (options);

        int hwms[2] = {conflate ? -1 : options.rcvhwm,
                       conflate ? -1 : options.sndhwm};
        bool conflates[2] = {conflate, conflate};
        int rc = pipepair (parents, pipes, hwms, conflates);
        errno_assert (rc == 0);

        //  Plug the local end of the pipe.
        pipes[0]->set_event_sink (this);

        //  Remember the local end of the pipe.
        zmq_assert (!_pipe);
        _pipe = pipes[0];

        //  The endpoints strings are not set on bind, set them here so that
        //  events can use them.
        pipes[0]->set_endpoint_pair (engine_->get_endpoint ());
        pipes[1]->set_endpoint_pair (engine_->get_endpoint ());

        //  Ask socket to plug into the remote end of the pipe.
        send_bind (_socket, pipes[1]);
    }

    //  Plug in the engine.
    zmq_assert (!_engine);
    _engine = engine_;
    _engine->plug (_io_thread, this);
}

void zmq::session_base_t::engine_error (zmq::i_engine::error_reason_t reason_)
{
    //  Engine is dead. Let's forget about it.
    _engine = NULL;

    //  Remove any half-done messages from the pipes.
    if (_pipe)
        clean_pipes ();

    zmq_assert (reason_ == i_engine::connection_error
                || reason_ == i_engine::timeout_error
                || reason_ == i_engine::protocol_error);

    switch (reason_) {
        case i_engine::timeout_error:
            /* FALLTHROUGH */
        case i_engine::connection_error:
            if (_active) {
                reconnect ();
                break;
            }
            /* FALLTHROUGH */
        case i_engine::protocol_error:
            if (_pending) {
                if (_pipe)
                    _pipe->terminate (false);
                if (_zap_pipe)
                    _zap_pipe->terminate (false);
            } else {
                terminate ();
            }
            break;
    }

    //  Just in case there's only a delimiter in the pipe.
    if (_pipe)
        _pipe->check_read ();

    if (_zap_pipe)
        _zap_pipe->check_read ();
}

void zmq::session_base_t::process_term (int linger_)
{
    zmq_assert (!_pending);

    //  If the termination of the pipe happens before the term command is
    //  delivered there's nothing much to do. We can proceed with the
    //  standard termination immediately.
    if (!_pipe && !_zap_pipe && _terminating_pipes.empty ()) {
        own_t::process_term (0);
        return;
    }

    _pending = true;

    if (_pipe != NULL) {
        //  If there's finite linger value, delay the termination.
        //  If linger is infinite (negative) we don't even have to set
        //  the timer.
        if (linger_ > 0) {
            zmq_assert (!_has_linger_timer);
            add_timer (linger_, linger_timer_id);
            _has_linger_timer = true;
        }

        //  Start pipe termination process. Delay the termination till all messages
        //  are processed in case the linger time is non-zero.
        _pipe->terminate (linger_ != 0);

        //  TODO: Should this go into pipe_t::terminate ?
        //  In case there's no engine and there's only delimiter in the
        //  pipe it wouldn't be ever read. Thus we check for it explicitly.
        if (!_engine)
            _pipe->check_read ();
    }

    if (_zap_pipe != NULL)
        _zap_pipe->terminate (false);
}

void zmq::session_base_t::timer_event (int id_)
{
    //  Linger period expired. We can proceed with termination even though
    //  there are still pending messages to be sent.
    zmq_assert (id_ == linger_timer_id);
    _has_linger_timer = false;

    //  Ask pipe to terminate even though there may be pending messages in it.
    zmq_assert (_pipe);
    _pipe->terminate (false);
}

void zmq::session_base_t::reconnect ()
{
    //  For delayed connect situations, terminate the pipe
    //  and reestablish later on
    if (_pipe && options.immediate == 1 && _addr->protocol != "pgm"
        && _addr->protocol != "epgm" && _addr->protocol != "norm"
        && _addr->protocol != protocol_name::udp) {
        _pipe->hiccup ();
        _pipe->terminate (false);
        _terminating_pipes.insert (_pipe);
        _pipe = NULL;

        if (_has_linger_timer) {
            cancel_timer (linger_timer_id);
            _has_linger_timer = false;
        }
    }

    reset ();

    //  Reconnect.
    if (options.reconnect_ivl != -1)
        start_connecting (true);
    else {
        std::string *ep = new (std::string);
        _addr->to_string (*ep);
        send_term_endpoint (_socket, ep);
    }

    //  For subscriber sockets we hiccup the inbound pipe, which will cause
    //  the socket object to resend all the subscriptions.
    if (_pipe
        && (options.type == ZMQ_SUB || options.type == ZMQ_XSUB
            || options.type == ZMQ_DISH))
        _pipe->hiccup ();
}

zmq::session_base_t::connecter_factory_entry_t
  zmq::session_base_t::_connecter_factories[] = {
    connecter_factory_entry_t (protocol_name::tcp,
                               &zmq::session_base_t::create_connecter_tcp),
    connecter_factory_entry_t (protocol_name::ws,
                               &zmq::session_base_t::create_connecter_ws),
#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS
    connecter_factory_entry_t (protocol_name::ipc,
                               &zmq::session_base_t::create_connecter_ipc),
#endif
#if defined ZMQ_HAVE_TIPC
    connecter_factory_entry_t (protocol_name::tipc,
                               &zmq::session_base_t::create_connecter_tipc),
#endif
#if defined ZMQ_HAVE_VMCI
    connecter_factory_entry_t (protocol_name::vmci,
                               &zmq::session_base_t::create_connecter_vmci),
#endif
};

zmq::session_base_t::connecter_factory_map_t
  zmq::session_base_t::_connecter_factories_map (
    _connecter_factories,
    _connecter_factories
      + sizeof (_connecter_factories) / sizeof (_connecter_factories[0]));

zmq::session_base_t::start_connecting_entry_t
  zmq::session_base_t::_start_connecting_entries[] = {
    start_connecting_entry_t (protocol_name::udp,
                              &zmq::session_base_t::start_connecting_udp),
#if defined ZMQ_HAVE_OPENPGM
    start_connecting_entry_t ("pgm",
                              &zmq::session_base_t::start_connecting_pgm),
    start_connecting_entry_t ("epgm",
                              &zmq::session_base_t::start_connecting_pgm),
#endif
#if defined ZMQ_HAVE_NORM
    start_connecting_entry_t ("norm",
                              &zmq::session_base_t::start_connecting_norm),
#endif
};

zmq::session_base_t::start_connecting_map_t
  zmq::session_base_t::_start_connecting_map (
    _start_connecting_entries,
    _start_connecting_entries
      + sizeof (_start_connecting_entries)
          / sizeof (_start_connecting_entries[0]));

void zmq::session_base_t::start_connecting (bool wait_)
{
    zmq_assert (_active);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create the connecter object.
    const connecter_factory_map_t::const_iterator connecter_factories_it =
      _connecter_factories_map.find (_addr->protocol);
    if (connecter_factories_it != _connecter_factories_map.end ()) {
        own_t *connecter =
          (this->*connecter_factories_it->second) (io_thread, wait_);

        alloc_assert (connecter);
        launch_child (connecter);
        return;
    }
    const start_connecting_map_t::const_iterator start_connecting_it =
      _start_connecting_map.find (_addr->protocol);
    if (start_connecting_it != _start_connecting_map.end ()) {
        (this->*start_connecting_it->second) (io_thread);
        return;
    }

    zmq_assert (false);
}

#if defined ZMQ_HAVE_VMCI
zmq::own_t *zmq::session_base_t::create_connecter_vmci (io_thread_t *io_thread_,
                                                        bool wait_)
{
    return new (std::nothrow)
      vmci_connecter_t (io_thread_, this, options, _addr, wait_);
}
#endif

#if defined ZMQ_HAVE_TIPC
zmq::own_t *zmq::session_base_t::create_connecter_tipc (io_thread_t *io_thread_,
                                                        bool wait_)
{
    return new (std::nothrow)
      tipc_connecter_t (io_thread_, this, options, _addr, wait_);
}
#endif

#if !defined ZMQ_HAVE_WINDOWS && !defined ZMQ_HAVE_OPENVMS                     \
  && !defined ZMQ_HAVE_VXWORKS
zmq::own_t *zmq::session_base_t::create_connecter_ipc (io_thread_t *io_thread_,
                                                       bool wait_)
{
    return new (std::nothrow)
      ipc_connecter_t (io_thread_, this, options, _addr, wait_);
}
#endif

zmq::own_t *zmq::session_base_t::create_connecter_tcp (io_thread_t *io_thread_,
                                                       bool wait_)
{
    if (!options.socks_proxy_address.empty ()) {
        address_t *proxy_address = new (std::nothrow) address_t (
          protocol_name::tcp, options.socks_proxy_address, this->get_ctx ());
        alloc_assert (proxy_address);
        socks_connecter_t *connecter = new (std::nothrow) socks_connecter_t (
          io_thread_, this, options, _addr, proxy_address, wait_);
        alloc_assert (connecter);
        if (!options.socks_proxy_username.empty ()) {
            connecter->set_auth_method_basic (options.socks_proxy_username,
                                              options.socks_proxy_password);
        }
        return connecter;
    }
    return new (std::nothrow)
      tcp_connecter_t (io_thread_, this, options, _addr, wait_);
}

zmq::own_t *zmq::session_base_t::create_connecter_ws (io_thread_t *io_thread_,
                                                      bool wait_)
{
    return new (std::nothrow)
      ws_connecter_t (io_thread_, this, options, _addr, wait_);
}

#ifdef ZMQ_HAVE_OPENPGM
void zmq::session_base_t::start_connecting_pgm (io_thread_t *io_thread_)
{
    zmq_assert (options.type == ZMQ_PUB || options.type == ZMQ_XPUB
                || options.type == ZMQ_SUB || options.type == ZMQ_XSUB);

    //  For EPGM transport with UDP encapsulation of PGM is used.
    bool const udp_encapsulation = _addr->protocol == "epgm";

    //  At this point we'll create message pipes to the session straight
    //  away. There's no point in delaying it as no concept of 'connect'
    //  exists with PGM anyway.
    if (options.type == ZMQ_PUB || options.type == ZMQ_XPUB) {
        //  PGM sender.
        pgm_sender_t *pgm_sender =
          new (std::nothrow) pgm_sender_t (io_thread_, options);
        alloc_assert (pgm_sender);

        int rc = pgm_sender->init (udp_encapsulation, _addr->address.c_str ());
        errno_assert (rc == 0);

        send_attach (this, pgm_sender);
    } else {
        //  PGM receiver.
        pgm_receiver_t *pgm_receiver =
          new (std::nothrow) pgm_receiver_t (io_thread_, options);
        alloc_assert (pgm_receiver);

        int rc =
          pgm_receiver->init (udp_encapsulation, _addr->address.c_str ());
        errno_assert (rc == 0);

        send_attach (this, pgm_receiver);
    }
}
#endif

#ifdef ZMQ_HAVE_NORM
void zmq::session_base_t::start_connecting_norm (io_thread_t *io_thread_)
{
    //  At this point we'll create message pipes to the session straight
    //  away. There's no point in delaying it as no concept of 'connect'
    //  exists with NORM anyway.
    if (options.type == ZMQ_PUB || options.type == ZMQ_XPUB) {
        //  NORM sender.
        norm_engine_t *norm_sender =
          new (std::nothrow) norm_engine_t (io_thread_, options);
        alloc_assert (norm_sender);

        int rc = norm_sender->init (_addr->address.c_str (), true, false);
        errno_assert (rc == 0);

        send_attach (this, norm_sender);
    } else { // ZMQ_SUB or ZMQ_XSUB

        //  NORM receiver.
        norm_engine_t *norm_receiver =
          new (std::nothrow) norm_engine_t (io_thread_, options);
        alloc_assert (norm_receiver);

        int rc = norm_receiver->init (_addr->address.c_str (), false, true);
        errno_assert (rc == 0);

        send_attach (this, norm_receiver);
    }
}
#endif

void zmq::session_base_t::start_connecting_udp (io_thread_t * /*io_thread_*/)
{
    zmq_assert (options.type == ZMQ_DISH || options.type == ZMQ_RADIO
                || options.type == ZMQ_DGRAM);

    udp_engine_t *engine = new (std::nothrow) udp_engine_t (options);
    alloc_assert (engine);

    const bool recv = options.type == ZMQ_DISH || options.type == ZMQ_DGRAM;
    const bool send = options.type == ZMQ_RADIO || options.type == ZMQ_DGRAM;

    const int rc = engine->init (_addr, send, recv);
    errno_assert (rc == 0);

    send_attach (this, engine);
}
