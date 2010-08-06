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

#include "object.hpp"
#include "yarray_item.hpp"
#include "mutex.hpp"
#include "options.hpp"
#include "stdint.hpp"
#include "atomic_counter.hpp"
#include "signaler.hpp"
#include "stdint.hpp"
#include "blob.hpp"

namespace zmq
{

    class socket_base_t :
        public object_t,
        public yarray_item_t
    {
    public:

        //  Create a socket of a specified type.
        static socket_base_t *create (int type_, class ctx_t *parent_,
            uint32_t slot_);

        //  Returns the signaler associated with this socket.
        signaler_t *get_signaler ();

        //  Interrupt blocking call if the socket is stuck in one.
        //  This function can be called from a different thread!
        void stop ();

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

        //  i_reader_events interface implementation.
        void activated (class reader_t *pipe_);
        void terminated (class reader_t *pipe_);

        //  i_writer_events interface implementation.
        void activated (class writer_t *pipe_);
        void terminated (class writer_t *pipe_);

        //  This function should be called only on zombie sockets. It tries
        //  to deallocate the zombie and returns true is successful.
        bool dezombify ();

    protected:

        socket_base_t (class ctx_t *parent_, uint32_t slot_);
        virtual ~socket_base_t ();

        //  Concrete algorithms for the x- methods are to be defined by
        //  individual socket types.

        virtual void xattach_pipes (class reader_t *inpipe_,
            class writer_t *outpipe_, const blob_t &peer_identity_) = 0;
        virtual void xterm_pipes () = 0;
        virtual bool xhas_pipes () = 0;

        //  The default implementation assumes there are no specific socket
        //  options for the particular socket type. If not so, overload this
        //  method.
        virtual int xsetsockopt (int option_, const void *optval_,
            size_t optvallen_);

        //  The default implementation assumes that send is not supported.
        virtual bool xhas_out ();
        virtual int xsend (zmq_msg_t *msg_, int options_);

        //  The default implementation assumes that recv in not supported.
        virtual bool xhas_in ();
        virtual int xrecv (zmq_msg_t *msg_, int options_);

        //  Socket options.
        options_t options;

        //  If true, socket was already closed but not yet deallocated
        //  because either shutdown is in process or there are still pipes
        //  attached to the socket.
        bool zombie;

    private:

        //  If no identity set generate one and call xattach_pipes ().
        void attach_pipes (class reader_t *inpipe_, class writer_t *outpipe_,
            const blob_t &peer_identity_);

        //  Processes commands sent to this socket (if any). If 'block' is
        //  set to true, returns only after at least one command was processed.
        //  If throttle argument is true, commands are processed at most once
        //  in a predefined time period.
        void process_commands (bool block_, bool throttle_);

        //  Handlers for incoming commands.
        void process_stop ();
        void process_own (class owned_t *object_);
        void process_bind (class reader_t *in_pipe_, class writer_t *out_pipe_,
            const blob_t &peer_identity_);
        void process_term_req (class owned_t *object_);
        void process_term_ack ();
        void process_seqnum ();

        //  App thread's signaler object.
        signaler_t signaler;

        //  Timestamp of when commands were processed the last time.
        uint64_t last_processing_time;

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
