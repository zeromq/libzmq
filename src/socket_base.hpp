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

#ifndef __ZMQ_SOCKET_BASE_HPP_INCLUDED__
#define __ZMQ_SOCKET_BASE_HPP_INCLUDED__

#include <set>
#include <map>
#include <vector>
#include <string>

#include "i_endpoint.hpp"
#include "object.hpp"
#include "mutex.hpp"
#include "options.hpp"
#include "stdint.hpp"

namespace zmq
{

    class socket_base_t : public object_t, public i_endpoint
    {
    public:

        socket_base_t (class app_thread_t *parent_);
        ~socket_base_t ();

        //  Interface for communication with the API layer.
        virtual int setsockopt (int option_, const void *optval_,
            size_t optvallen_);
        virtual int bind (const char *addr_);
        virtual int connect (const char *addr_);
        virtual int send (struct zmq_msg_t *msg_, int flags_);
        virtual int flush ();
        virtual int recv (struct zmq_msg_t *msg_, int flags_);
        virtual int close ();

        //  The list of sessions cannot be accessed via inter-thread
        //  commands as it is unacceptable to wait for the completion of the
        //  action till user application yields control of the application
        //  thread to 0MQ.
        bool register_session (const char *name_, class session_t *session_);
        bool unregister_session (const char *name_);
        class session_t *find_session (const char *name_);

        //  i_endpoint interface implementation.
        void attach_inpipe (class reader_t *pipe_);
        void attach_outpipe (class writer_t *pipe_);
        void revive (class reader_t *pipe_);
        void detach_inpipe (class reader_t *pipe_);
        void detach_outpipe (class writer_t *pipe_);

        //  Manipulating index in the app_thread's list of sockets.
        void set_index (int index);
        int get_index ();

    private:

        //  Handlers for incoming commands.
        void process_own (class owned_t *object_);
        void process_bind (class owned_t *session_,
            class reader_t *in_pipe_, class writer_t *out_pipe_);
        void process_term_req (class owned_t *object_);
        void process_term_ack ();

        //  Attempts to distribute the message to all the outbound pipes.
        //  Returns false if not possible because of pipe overflow.
        bool distribute (struct zmq_msg_t *msg_, bool flush_);

        //  Gets a message from one of the inbound pipes. Implementation of
        //  fair queueing.
        bool fetch (struct zmq_msg_t *msg_);

        //  List of all I/O objects owned by this socket. The socket is
        //  responsible for deallocating them before it quits.
        typedef std::set <class owned_t*> io_objects_t;
        io_objects_t io_objects;

        //  Inbound pipes, i.e. those the socket is getting messages from.
        typedef std::vector <class reader_t*> in_pipes_t;
        in_pipes_t in_pipes;

        //  Index of the next inbound pipe to read messages from.
        in_pipes_t::size_type current;

        //  Number of active inbound pipes. Active pipes are stored in the
        //  initial section of the in_pipes array.
        in_pipes_t::size_type active;

        //  Outbound pipes, i.e. those the socket is sending messages to.
        typedef std::vector <class writer_t*> out_pipes_t;
        out_pipes_t out_pipes;

        //  Number of I/O objects that were already asked to terminate
        //  but haven't acknowledged it yet.
        int pending_term_acks;

        //  Number of messages received since last command processing.
        int ticks;

        //  Application thread the socket lives in.
        class app_thread_t *app_thread;

        //  Socket options.
        options_t options;

        //  If true, socket is already shutting down. No new work should be
        //  started.
        bool shutting_down;

        //  List of existing sessions. This list is never referenced from within
        //  the socket, instead it is used by I/O objects owned by the session.
        //  As those objects can live in different threads, the access is
        //  synchronised using 'sessions_sync' mutex.
        //  Local sessions are those named by the local instance of 0MQ.
        //  Remote sessions are the sessions who's identities are provided by
        //  the remote party.
        typedef std::map <std::string, session_t*> sessions_t;
        sessions_t sessions;
        mutex_t sessions_sync;

        //  Index of the socket in the app_thread's list of sockets.
        int index;

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
