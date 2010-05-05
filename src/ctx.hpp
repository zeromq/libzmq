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

#ifndef __ZMQ_CTX_HPP_INCLUDED__
#define __ZMQ_CTX_HPP_INCLUDED__

#include <vector>
#include <set>
#include <map>
#include <string>

#include "signaler.hpp"
#include "ypipe.hpp"
#include "config.hpp"
#include "mutex.hpp"
#include "stdint.hpp"
#include "thread.hpp"

namespace zmq
{

    //  Context object encapsulates all the global state associated with
    //  the library.
    
    class ctx_t
    {
    public:

        //  Create the context object. The argument specifies the size
        //  of I/O thread pool to create.
        ctx_t (uint32_t io_threads_);

        //  This function is called when user invokes zmq_term. If there are
        //  no more sockets open it'll cause all the infrastructure to be shut
        //  down. If there are open sockets still, the deallocation happens
        //  after the last one is closed.
        int term ();

        //  Create a socket.
        class socket_base_t *create_socket (int type_);

        //  Destroy a socket.
        void destroy_socket ();

        //  Called by app_thread_t when it has no more sockets. The function
        //  should disassociate the object from the current OS thread.
        void no_sockets (class app_thread_t *thread_);

        //  Send command to the destination thread.
        void send_command (uint32_t destination_, const command_t &command_);

        //  Receive command from another thread.
        bool recv_command (uint32_t thread_slot_, command_t *command_,
            bool block_);

        //  Returns the I/O thread that is the least busy at the moment.
        //  Taskset specifies which I/O threads are eligible (0 = all).
        class io_thread_t *choose_io_thread (uint64_t taskset_);

        //  All pipes are registered with the context so that even the
        //  orphaned pipes can be deallocated on the terminal shutdown.
        void register_pipe (class pipe_t *pipe_);
        void unregister_pipe (class pipe_t *pipe_);

        //  Management of inproc endpoints.
        int register_endpoint (const char *addr_, class socket_base_t *socket_);
        void unregister_endpoints (class socket_base_t *socket_);
        class socket_base_t *find_endpoint (const char *addr_);

    private:

        ~ctx_t ();

        struct app_thread_info_t
        {
            //  If false, 0MQ application thread is free, there's no associated
            //  OS thread.
            bool associated;

            //  ID of the associated OS thread. If 'associated' is false,
            //  this field contains bogus data.
            thread_t::id_t tid;

            //  Pointer to the 0MQ application thread object.
            class app_thread_t *app_thread;
        };

        //  Application threads.
        typedef std::vector <app_thread_info_t> app_threads_t;
        app_threads_t app_threads;

        //  Synchronisation of accesses to shared application thread data.
        mutex_t app_threads_sync;

        //  I/O threads.
        typedef std::vector <class io_thread_t*> io_threads_t;
        io_threads_t io_threads;

        //  Array of pointers to signalers for both application and I/O threads.
        int signalers_count;
        signaler_t **signalers;

        //  As pipes may reside in orphaned state in particular moments
        //  of the pipe shutdown process, i.e. neither pipe reader nor
        //  pipe writer hold reference to the pipe, we have to hold references
        //  to all pipes in context so that we can deallocate them
        //  during terminal shutdown even though it conincides with the
        //  pipe being in the orphaned state.
        typedef std::set <class pipe_t*> pipes_t;
        pipes_t pipes;

        //  Synchronisation of access to the pipes repository.
        mutex_t pipes_sync;

        //  Number of sockets alive.
        int sockets;

        //  If true, zmq_term was already called. When last socket is closed
        //  the whole 0MQ infrastructure should be deallocated.
        bool terminated;

        //  Synchronisation of access to the termination data (socket count
        //  and 'terminated' flag).
        mutex_t term_sync;

        //  List of inproc endpoints within this context.
        typedef std::map <std::string, class socket_base_t*> endpoints_t;
        endpoints_t endpoints;

        //  Synchronisation of access to the list of inproc endpoints.
        mutex_t endpoints_sync;

        ctx_t (const ctx_t&);
        void operator = (const ctx_t&);
    };
    
}

#endif

