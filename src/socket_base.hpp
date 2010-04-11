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

#ifndef __ZMQ_SOCKET_BASE_HPP_INCLUDED__
#define __ZMQ_SOCKET_BASE_HPP_INCLUDED__

#include <set>
#include <map>
#include <vector>

#include "../include/zmq.h"

#include "i_endpoint.hpp"
#include "object.hpp"
#include "yarray_item.hpp"
#include "mutex.hpp"
#include "options.hpp"
#include "stdint.hpp"
#include "atomic_counter.hpp"
#include "stdint.hpp"
#include "blob.hpp"

namespace zmq
{

    class socket_base_t :
        public object_t, public i_endpoint, public yarray_item_t
    {
    public:

        socket_base_t (class app_thread_t *parent_);

        //  Interface for communication with the API layer.
        int setsockopt (int option_, const void *optval_, size_t optvallen_);
        int getsockopt (int option_, void *optval_, size_t *optvallen_);
        int bind (const char *addr_);
        int connect (const char *addr_);
        int send (zmq_msg_t *msg_, int flags_);
        int recv (zmq_msg_t *msg_, int flags_);
        int close ();

        //  When another owned object wants to send command to this object
        //  it calls this function to let it know it should not shut down
        //  before the command is delivered.
        void inc_seqnum ();

        //  This function is used by the polling mechanism to determine
        //  whether the socket belongs to the application thread the poll
        //  is called from.
        class app_thread_t *get_thread ();

        //  These functions are used by the polling mechanism to determine
        //  which events are to be reported from this socket.
        bool has_in ();
        bool has_out ();

        //  The list of sessions cannot be accessed via inter-thread
        //  commands as it is unacceptable to wait for the completion of the
        //  action till user application yields control of the application
        //  thread to 0MQ. Locking is used instead.
        //  There are two distinct types of sessions: those identified by name
        //  and those identified by ordinal number. Thus two sets of session
        //  management functions.
        bool register_session (const blob_t &peer_identity_,
            class session_t *session_);
        void unregister_session (const blob_t &peer_identity_);
        class session_t *find_session (const blob_t &peer_identity_);
        uint64_t register_session (class session_t *session_);
        void unregister_session (uint64_t ordinal_);
        class session_t *find_session (uint64_t ordinal_);

        //  i_endpoint interface implementation.
        void attach_pipes (class reader_t *inpipe_, class writer_t *outpipe_,
            const blob_t &peer_identity_);
        void detach_inpipe (class reader_t *pipe_);
        void detach_outpipe (class writer_t *pipe_);
        void kill (class reader_t *pipe_);
        void revive (class reader_t *pipe_);
        void revive (class writer_t *pipe_);

    protected:

        //  Destructor is protected. Socket is closed using 'close' function.
        virtual ~socket_base_t ();

        //  Pipe management is done by individual socket types.
        virtual void xattach_pipes (class reader_t *inpipe_,
            class writer_t *outpipe_, const blob_t &peer_identity_) = 0;
        virtual void xdetach_inpipe (class reader_t *pipe_) = 0;
        virtual void xdetach_outpipe (class writer_t *pipe_) = 0;
        virtual void xkill (class reader_t *pipe_) = 0;
        virtual void xrevive (class reader_t *pipe_) = 0;
        virtual void xrevive (class writer_t *pipe_) = 0;

        //  Actual algorithms are to be defined by individual socket types.
        virtual int xsetsockopt (int option_, const void *optval_,
            size_t optvallen_) = 0;
        virtual int xsend (zmq_msg_t *msg_, int options_) = 0;
        virtual int xrecv (zmq_msg_t *msg_, int options_) = 0;
        virtual bool xhas_in () = 0;
        virtual bool xhas_out () = 0;

        //  Socket options.
        options_t options;

    private:

        //  Handlers for incoming commands.
        void process_own (class owned_t *object_);
        void process_bind (class reader_t *in_pipe_, class writer_t *out_pipe_,
            const blob_t &peer_identity_);
        void process_term_req (class owned_t *object_);
        void process_term_ack ();
        void process_seqnum ();

        //  List of all I/O objects owned by this socket. The socket is
        //  responsible for deallocating them before it quits.
        typedef std::set <class owned_t*> io_objects_t;
        io_objects_t io_objects;

        //  Number of I/O objects that were already asked to terminate
        //  but haven't acknowledged it yet.
        int pending_term_acks;

        //  Number of messages received since last command processing.
        int ticks;

        //  If true there's a half-read message in the socket.
        bool rcvmore;

        //  Application thread the socket lives in.
        class app_thread_t *app_thread;

        //  If true, socket is already shutting down. No new work should be
        //  started.
        bool shutting_down;

        //  Sequence number of the last command sent to this object.
        atomic_counter_t sent_seqnum;

        //  Sequence number of the last command processed by this object.
        uint64_t processed_seqnum;

        //  Lists of existing sessions. This lists are never referenced from
        //  within the socket, instead they are used by I/O objects owned by
        //  the socket. As those objects can live in different threads,
        //  the access is synchronised by mutex.
        typedef std::map <blob_t, session_t*> named_sessions_t;
        named_sessions_t named_sessions;
        typedef std::map <uint64_t, session_t*> unnamed_sessions_t;
        unnamed_sessions_t unnamed_sessions;
        uint64_t next_ordinal;
        mutex_t sessions_sync;

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
