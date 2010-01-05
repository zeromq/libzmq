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

#ifndef __ZMQ_DISPATCHER_HPP_INCLUDED__
#define __ZMQ_DISPATCHER_HPP_INCLUDED__

#include <vector>
#include <set>
#include <map>
#include <string>

#include "i_signaler.hpp"
#include "ypipe.hpp"
#include "command.hpp"
#include "config.hpp"
#include "mutex.hpp"
#include "stdint.hpp"

namespace zmq
{

    //  Dispatcher implements bidirectional thread-safe passing of commands
    //  between N threads. It consists of a ypipes to pass commands and
    //  signalers to wake up the receiver thread when new commands are
    //  available. Note that dispatcher is inefficient for passing messages
    //  within a thread (sender thread = receiver thread). The optimisation is
    //  not part of the class and should be implemented by individual threads
    //  (presumably by calling the command handling function directly).
    
    class dispatcher_t
    {
    public:

        //  Create the dispatcher object. Matrix of pipes to communicate between
        //  each socket and each I/O thread is created along with appropriate
        //  signalers.
        dispatcher_t (int app_threads_, int io_threads_, int flags_);

        //  This function is called when user invokes zmq_term. If there are
        //  no more sockets open it'll cause all the infrastructure to be shut
        //  down. If there are open sockets still, the deallocation happens
        //  after the last one is closed.
        int term ();

        //  Create a socket.
        class socket_base_t *create_socket (int type_);

        //  Destroy a socket.
        void destroy_socket ();

        //  Returns number of thread slots in the dispatcher. To be used by
        //  individual threads to find out how many distinct signals can be
        //  received.
        int thread_slot_count ();

        //  Send command from the source to the destination.
        inline void write (int source_, int destination_,
            const command_t &command_)
        {
            command_pipe_t &pipe =
                command_pipes [source_ * signalers.size () + destination_];
            pipe.write (command_);
            if (!pipe.flush ())
                signalers [destination_]->signal (source_);
        }

        //  Receive command from the source. Returns false if there is no
        //  command available.
        inline bool read (int source_,  int destination_, command_t *command_)
        {
            return command_pipes [source_ * signalers.size () +
                destination_].read (command_);
        }

        //  Returns the I/O thread that is the least busy at the moment.
        //  Taskset specifies which I/O threads are eligible (0 = all).
        class io_thread_t *choose_io_thread (uint64_t taskset_);

        //  All pipes are registered with the dispatcher so that even the
        //  orphaned pipes can be deallocated on the terminal shutdown.
        void register_pipe (class pipe_t *pipe_);
        void unregister_pipe (class pipe_t *pipe_);

        //  Management of inproc endpoints.
        int register_endpoint (const char *addr_, class socket_base_t *socket_);
        void unregister_endpoints (class socket_base_t *socket_);
        class socket_base_t *find_endpoint (const char *addr_);

    private:

        ~dispatcher_t ();

        //  Returns the app thread associated with the current thread.
        //  NULL if we are out of app thread slots.
        class app_thread_t *choose_app_thread ();

        //  Application threads.
        typedef std::vector <class app_thread_t*> app_threads_t;
        app_threads_t app_threads;

        //  I/O threads.
        typedef std::vector <class io_thread_t*> io_threads_t;
        io_threads_t io_threads;

        //  Signalers for both application and I/O threads.
        std::vector <i_signaler*> signalers;

        //  Pipe to hold the commands.
        typedef ypipe_t <command_t, true,
            command_pipe_granularity> command_pipe_t;

        //  NxN matrix of command pipes.
        command_pipe_t *command_pipes;

        //  Synchronisation of accesses to shared thread data.
        mutex_t threads_sync;

        //  As pipes may reside in orphaned state in particular moments
        //  of the pipe shutdown process, i.e. neither pipe reader nor
        //  pipe writer hold reference to the pipe, we have to hold references
        //  to all pipes in dispatcher so that we can deallocate them
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

        dispatcher_t (const dispatcher_t&);
        void operator = (const dispatcher_t&);
    };
    
}

#endif

