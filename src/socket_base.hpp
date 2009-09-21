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
#include "yarray_item.hpp"
#include "mutex.hpp"
#include "options.hpp"
#include "stdint.hpp"

namespace zmq
{

    class socket_base_t :
        public object_t, public i_endpoint, public yarray_item_t
    {
    public:

        socket_base_t (class app_thread_t *parent_);

        //  Interface for communication with the API layer.
        int setsockopt (int option_, const void *optval_,
            size_t optvallen_);
        int bind (const char *addr_);
        int connect (const char *addr_);
        int send (struct zmq_msg_t *msg_, int flags_);
        int flush ();
        int recv (struct zmq_msg_t *msg_, int flags_);
        int close ();

        //  The list of sessions cannot be accessed via inter-thread
        //  commands as it is unacceptable to wait for the completion of the
        //  action till user application yields control of the application
        //  thread to 0MQ. Locking is used instead.
        bool register_session (const char *name_, class session_t *session_);
        bool unregister_session (const char *name_);
        class session_t *find_session (const char *name_);

        //  i_endpoint interface implementation.
        void attach_pipes (class reader_t *inpipe_, class writer_t *outpipe_);
        void detach_inpipe (class reader_t *pipe_);
        void detach_outpipe (class writer_t *pipe_);
        void kill (class reader_t *pipe_);
        void revive (class reader_t *pipe_);

    protected:

        //  Destructor is protected. Socket is closed using 'close' function.
        virtual ~socket_base_t ();

        //  Pipe management is done by individual socket types.
        virtual void xattach_pipes (class reader_t *inpipe_,
            class writer_t *outpipe_) = 0;
        virtual void xdetach_inpipe (class reader_t *pipe_) = 0;
        virtual void xdetach_outpipe (class writer_t *pipe_) = 0;
        virtual void xkill (class reader_t *pipe_) = 0;
        virtual void xrevive (class reader_t *pipe_) = 0;

        //  Actual algorithms are to be defined by individual socket types.
        virtual int xsetsockopt (int option_, const void *optval_,
            size_t optvallen_) = 0;
        virtual int xsend (struct zmq_msg_t *msg_, int options_) = 0;
        virtual int xflush () = 0;
        virtual int xrecv (struct zmq_msg_t *msg_, int options_) = 0;

        //  Socket options.
        options_t options;

    private:

        //  Handlers for incoming commands.
        void process_own (class owned_t *object_);
        void process_bind (class owned_t *session_,
            class reader_t *in_pipe_, class writer_t *out_pipe_);
        void process_term_req (class owned_t *object_);
        void process_term_ack ();

        //  List of all I/O objects owned by this socket. The socket is
        //  responsible for deallocating them before it quits.
        typedef std::set <class owned_t*> io_objects_t;
        io_objects_t io_objects;

        //  Number of I/O objects that were already asked to terminate
        //  but haven't acknowledged it yet.
        int pending_term_acks;

        //  Number of messages received since last command processing.
        int ticks;

        //  Application thread the socket lives in.
        class app_thread_t *app_thread;

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

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
