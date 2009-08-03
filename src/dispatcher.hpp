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

#ifndef __ZMQ_DISPATCHER_HPP_INCLUDED__
#define __ZMQ_DISPATCHER_HPP_INCLUDED__

#include <vector>
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
        dispatcher_t (int app_threads_, int io_threads_);

        //  To be called to terminate the whole infrastructure (zmq_term).
        void shutdown ();

        //  Create a socket engine.
        struct i_api *create_socket (int type_);

        //  Returns number of thread slots in the dispatcher. To be used by
        //  individual threads to find out how many distinct signals can be
        //  received.
        int thread_slot_count ();

        //  Write command to the dispatcher.
        inline void write (int source_, int destination_,
            const command_t &command_)
        {
            command_pipe_t &pipe =
                command_pipes [source_ * signalers.size () + destination_];
            pipe.write (command_);
            if (!pipe.flush ())
                signalers [destination_]->signal (source_);
        }

        //  Read command from the dispatcher. Returns false if there is no
        //  command available.
        inline bool read (int source_,  int destination_, command_t *command_)
        {
            return command_pipes [source_ * signalers.size () +
                destination_].read (command_);
        }

        //  Creates new pipe.
        void create_pipe (class object_t *reader_parent_,
            class object_t *writer_parent_, uint64_t hwm_, uint64_t lwm_,
            class pipe_reader_t **reader_, class pipe_writer_t **writer_);

        //  Deallocates the pipe.
        void destroy_pipe (class pipe_t *pipe_);

        //  Registers existing session object as an inproc endpoint.
        int register_inproc_endpoint (const char *endpoint_,
            class session_t *session_);

        //  Retrieves an inproc endpoint. Increments the command sequence number
        //  of the object by one. Caller is thus bound to send the command
        //  to the connection after invoking this function. Returns NULL if
        //  the endpoint doesn't exist.
        class object_t *get_inproc_endpoint (const char *endpoint_);

        //  Removes all the inproc endpoints associated with the given session
        //  object from the global repository.
        void unregister_inproc_endpoints (class session_t *session_);

        //  Returns the I/O thread that is the least busy at the moment.
        //  Taskset specifies which I/O threads are eligible (0 = all).
        class io_thread_t *choose_io_thread (uint64_t taskset_);

    private:

        //  Clean-up.
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

        //  Global repository of pipes. It's used only on terminal shutdown
        //  to deallocate all the pipes irrespective of whether they are
        //  referenced from pipe_reader, pipe_writer or both.
        struct pipe_info_t
        {
            class pipe_t *pipe;
            class pipe_reader_t *reader;
            class pipe_writer_t *writer;
        };
        typedef std::vector <pipe_info_t> pipes_t;
        pipes_t pipes;

        //  Synchronisation of access to global repository of pipes.
        mutex_t pipes_sync;

        //  Global repository of available inproc endpoints.
        typedef std::map <std::string, class session_t*> inproc_endpoints_t;
        inproc_endpoints_t inproc_endpoints;

        //  Synchronisation of access to the global repository
        //  of inproc endpoints.
        mutex_t inproc_endpoint_sync;

        dispatcher_t (const dispatcher_t&);
        void operator = (const dispatcher_t&);
    };
    
}

#endif

