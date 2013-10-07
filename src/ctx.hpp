/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

    struct pending_connection_t
    {
        endpoint_t endpoint;
        pipe_t* connect_pipe;
        pipe_t* bind_pipe;
    };

    //  Context object encapsulates all the global state associated with
    //  the library.

    class ctx_t
    {
    public:

        //  Create the context object.
        ctx_t ();

        //  Returns false if object is not a context.
        bool check_tag ();

        //  This function is called when user invokes zmq_term. If there are
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
        int shutdown();

        //  Set and get context properties.
        int set (int option_, int optval_);
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
        int register_endpoint (const char *addr_, endpoint_t &endpoint_);
        void unregister_endpoints (zmq::socket_base_t *socket_);
        endpoint_t find_endpoint (const char *addr_);
        void pend_connection (const char *addr_, pending_connection_t &pending_connection_);
        void connect_pending (const char *addr_, zmq::socket_base_t *bind_socket_);

        enum {
            term_tid = 0,
            reaper_tid = 1
        };

        ~ctx_t ();

    private:


        //  Used to check whether the object is a context.
        uint32_t tag;

        //  Sockets belonging to this context. We need the list so that
        //  we can notify the sockets when zmq_term() is called. The sockets
        //  will return ETERM then.
        typedef array_t <socket_base_t> sockets_t;
        sockets_t sockets;

        //  List of unused thread slots.
        typedef std::vector <uint32_t> empty_slots_t;
        empty_slots_t empty_slots;

        //  If true, zmq_init has been called but no socket has been created
        //  yet. Launching of I/O threads is delayed.
        bool starting;

        //  If true, zmq_term was already called.
        bool terminating;

        //  Synchronisation of accesses to global slot-related data:
        //  sockets, empty_slots, terminating. It also synchronises
        //  access to zombie sockets as such (as opposed to slots) and provides
        //  a memory barrier to ensure that all CPU cores see the same data.
        mutex_t slot_sync;

        //  The reaper thread.
        zmq::reaper_t *reaper;

        //  I/O threads.
        typedef std::vector <zmq::io_thread_t*> io_threads_t;
        io_threads_t io_threads;

        //  Array of pointers to mailboxes for both application and I/O threads.
        uint32_t slot_count;
        mailbox_t **slots;

        //  Mailbox for zmq_term thread.
        mailbox_t term_mailbox;

        //  List of inproc endpoints within this context.
        typedef std::map <std::string, endpoint_t> endpoints_t;
        endpoints_t endpoints;

        // List of inproc connection endpoints pending a bind
        typedef std::multimap <std::string, pending_connection_t> pending_connections_t;
        pending_connections_t pending_connections;

        //  Synchronisation of access to the list of inproc endpoints.
        mutex_t endpoints_sync;

        //  Maximum socket ID.
        static atomic_counter_t max_socket_id;

        //  Maximum number of sockets that can be opened at the same time.
        int max_sockets;

        //  Number of I/O threads to launch.
        int io_thread_count;

        //  Is IPv6 enabled on this context?
        bool ipv6;

        //  Synchronisation of access to context options.
        mutex_t opt_sync;

        ctx_t (const ctx_t&);
        const ctx_t &operator = (const ctx_t&);

#ifdef HAVE_FORK
        // the process that created this context. Used to detect forking.
        pid_t pid;
#endif
        enum side { connect_side, bind_side };
        void connect_inproc_sockets(zmq::socket_base_t *bind_socket_, options_t& bind_options, pending_connection_t &pending_connection_, side side_);
    };

}

#endif
