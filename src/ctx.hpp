/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_CTX_HPP_INCLUDED__
#define __ZMQ_CTX_HPP_INCLUDED__

#include <map>
#include <vector>
#include <string>
#include <stdarg.h>

#include "mailbox.hpp"
#include "array.hpp"
#include "config.hpp"
#include "mutex.hpp"
#include "stdint.hpp"
#include "options.hpp"
#include "atomic_counter.hpp"
#include "thread.hpp"

namespace zmq
{
class object_t;
class io_thread_t;
class socket_base_t;
class reaper_t;
class pipe_t;

//  Information associated with inproc endpoint. Note that endpoint options
//  are registered as well so that the peer can access them without a need
//  for synchronisation, handshaking or similar.
struct endpoint_t
{
    socket_base_t *socket;
    options_t options;
};

class thread_ctx_t
{
  public:
    thread_ctx_t ();

    //  Start a new thread with proper scheduling parameters.
    void start_thread (thread_t &thread_,
                       thread_fn *tfn_,
                       void *arg_,
                       const char *name_ = NULL) const;

    int set (int option_, const void *optval_, size_t optvallen_);
    int get (int option_, void *optval_, size_t *optvallen_);

  protected:
    //  Synchronisation of access to context options.
    mutex_t _opt_sync;

  private:
    //  Thread parameters.
    int _thread_priority;
    int _thread_sched_policy;
    std::set<int> _thread_affinity_cpus;
    std::string _thread_name_prefix;
};

//  Context object encapsulates all the global state associated with
//  the library.

class ctx_t : public thread_ctx_t
{
  public:
    //  Create the context object.
    ctx_t ();

    //  Returns false if object is not a context.
    bool check_tag ();

    //  This function is called when user invokes zmq_ctx_term. If there are
    //  no more sockets open it'll cause all the infrastructure to be shut
    //  down. If there are open sockets still, the deallocation happens
    //  after the last one is closed.
    int terminate ();

    // This function starts the terminate process by unblocking any blocking
    // operations currently in progress and stopping any more socket activity
    // (except zmq_close).
    // This function is non-blocking.
    // terminate must still be called afterwards.
    // This function is optional, terminate will unblock any current
    // operations as well.
    int shutdown ();

    //  Set and get context properties.
    int set (int option_, const void *optval_, size_t optvallen_);
    int get (int option_, void *optval_, size_t *optvallen_);
    int get (int option_);

    //  Create and destroy a socket.
    zmq::socket_base_t *create_socket (int type_);
    void destroy_socket (zmq::socket_base_t *socket_);

    //  Send command to the destination thread.
    void send_command (uint32_t tid_, const command_t &command_);

    //  Returns the I/O thread that is the least busy at the moment.
    //  Affinity specifies which I/O threads are eligible (0 = all).
    //  Returns NULL if no I/O thread is available.
    zmq::io_thread_t *choose_io_thread (uint64_t affinity_);

    //  Returns reaper thread object.
    zmq::object_t *get_reaper ();

    //  Management of inproc endpoints.
    int register_endpoint (const char *addr_, const endpoint_t &endpoint_);
    int unregister_endpoint (const std::string &addr_, socket_base_t *socket_);
    void unregister_endpoints (zmq::socket_base_t *socket_);
    endpoint_t find_endpoint (const char *addr_);
    void pend_connection (const std::string &addr_,
                          const endpoint_t &endpoint_,
                          pipe_t **pipes_);
    void connect_pending (const char *addr_, zmq::socket_base_t *bind_socket_);

#ifdef ZMQ_HAVE_VMCI
    // Return family for the VMCI socket or -1 if it's not available.
    int get_vmci_socket_family ();
#endif

    enum
    {
        term_tid = 0,
        reaper_tid = 1
    };

    ~ctx_t ();

    bool valid () const;

  private:
    bool start ();

    struct pending_connection_t
    {
        endpoint_t endpoint;
        pipe_t *connect_pipe;
        pipe_t *bind_pipe;
    };

    //  Used to check whether the object is a context.
    uint32_t _tag;

    //  Sockets belonging to this context. We need the list so that
    //  we can notify the sockets when zmq_ctx_term() is called.
    //  The sockets will return ETERM then.
    typedef array_t<socket_base_t> sockets_t;
    sockets_t _sockets;

    //  List of unused thread slots.
    typedef std::vector<uint32_t> empty_slots_t;
    empty_slots_t _empty_slots;

    //  If true, zmq_init has been called but no socket has been created
    //  yet. Launching of I/O threads is delayed.
    bool _starting;

    //  If true, zmq_ctx_term was already called.
    bool _terminating;

    //  Synchronisation of accesses to global slot-related data:
    //  sockets, empty_slots, terminating. It also synchronises
    //  access to zombie sockets as such (as opposed to slots) and provides
    //  a memory barrier to ensure that all CPU cores see the same data.
    mutex_t _slot_sync;

    //  The reaper thread.
    zmq::reaper_t *_reaper;

    //  I/O threads.
    typedef std::vector<zmq::io_thread_t *> io_threads_t;
    io_threads_t _io_threads;

    //  Array of pointers to mailboxes for both application and I/O threads.
    std::vector<i_mailbox *> _slots;

    //  Mailbox for zmq_ctx_term thread.
    mailbox_t _term_mailbox;

    //  List of inproc endpoints within this context.
    typedef std::map<std::string, endpoint_t> endpoints_t;
    endpoints_t _endpoints;

    // List of inproc connection endpoints pending a bind
    typedef std::multimap<std::string, pending_connection_t>
      pending_connections_t;
    pending_connections_t _pending_connections;

    //  Synchronisation of access to the list of inproc endpoints.
    mutex_t _endpoints_sync;

    //  Maximum socket ID.
    static atomic_counter_t max_socket_id;

    //  Maximum number of sockets that can be opened at the same time.
    int _max_sockets;

    //  Maximum allowed message size
    int _max_msgsz;

    //  Number of I/O threads to launch.
    int _io_thread_count;

    //  Does context wait (possibly forever) on termination?
    bool _blocky;

    //  Is IPv6 enabled on this context?
    bool _ipv6;

    // Should we use zero copy message decoding in this context?
    bool _zero_copy;

    ctx_t (const ctx_t &);
    const ctx_t &operator= (const ctx_t &);

#ifdef HAVE_FORK
    // the process that created this context. Used to detect forking.
    pid_t _pid;
#endif
    enum side
    {
        connect_side,
        bind_side
    };
    void
    connect_inproc_sockets (zmq::socket_base_t *bind_socket_,
                            options_t &bind_options_,
                            const pending_connection_t &pending_connection_,
                            side side_);

#ifdef ZMQ_HAVE_VMCI
    int _vmci_fd;
    int _vmci_family;
    mutex_t _vmci_sync;
#endif
};
}

#endif
