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
#include "semaphore.hpp"
#include "ypipe.hpp"
#include "yarray.hpp"
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

        //  Make socket a zombie.
        void zombify (socket_base_t *socket_);

        //  Send command to the destination slot.
        void send_command (uint32_t slot_, const command_t &command_);

        //  Receive command from the source slot.
        bool recv_command (uint32_t slot_, command_t *command_, bool block_);

        //  Returns the I/O thread that is the least busy at the moment.
        //  Taskset specifies which I/O threads are eligible (0 = all).
        class io_thread_t *choose_io_thread (uint64_t taskset_);

        //  Management of inproc endpoints.
        int register_endpoint (const char *addr_, class socket_base_t *socket_);
        void unregister_endpoints (class socket_base_t *socket_);
        class socket_base_t *find_endpoint (const char *addr_);

    private:

        ~ctx_t ();

        //  Sockets belonging to this context.
        typedef yarray_t <socket_base_t> sockets_t;
        sockets_t sockets;

        //  Array of sockets that were already closed but not yet deallocated.
        //  These sockets still have some pipes and I/O objects attached.
        typedef yarray_t <socket_base_t> zombies_t;
        zombies_t zombies;

        //  List of unused slots.
        typedef std::vector <uint32_t> emtpy_slots_t;
        emtpy_slots_t empty_slots;

        //  If true, shutdown thread wants to be informed when there are no
        //  more open sockets. Do so by posting no_sockets_sync semaphore.
        //  Note that this variable is synchronised by slot_sync mutex.
        bool no_sockets_notify;

        //  Object used by zmq_term to wait while all the sockets are closed
        //  by different application threads.
        semaphore_t no_sockets_sync;

        //  Synchronisation of accesses to global slot-related data:
        //  sockets, zombies, empty_slots, terminated. It also synchronises
        //  access to zombie sockets as such (as oposed to slots) and provides
        //  a memory barrier to ensure that all CPU cores see the same data.
        mutex_t slot_sync;

        //  This function attempts to deallocate as many zombie sockets as
        //  possible. It must be called within a slot_sync critical section.
        void dezombify ();

        //  I/O threads.
        typedef std::vector <class io_thread_t*> io_threads_t;
        io_threads_t io_threads;

        //  Array of pointers to signalers for both application and I/O threads.
        uint32_t slot_count;
        signaler_t **slots;

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

