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

#ifndef __ZMQ_PIPE_HPP_INCLUDED__
#define __ZMQ_PIPE_HPP_INCLUDED__

#include "../include/zmq.h"

#include "stdint.hpp"
#include "i_endpoint.hpp"
#include "yarray_item.hpp"
#include "ypipe.hpp"
#include "config.hpp"
#include "object.hpp"

namespace zmq
{

    class reader_t : public object_t, public yarray_item_t
    {
    public:

        reader_t (class object_t *parent_,
            uint64_t hwm_, uint64_t lwm_);
        ~reader_t ();

        void set_pipe (class pipe_t *pipe_);
        void set_endpoint (i_endpoint *endpoint_);

        //  Returns true if there is at least one message to read in the pipe.
        bool check_read ();

        //  Reads a message to the underlying pipe.
        bool read (zmq_msg_t *msg_);

        //  Ask pipe to terminate.
        void term ();

    private:

        //  Command handlers.
        void process_revive ();
        void process_pipe_term_ack ();

        //  The underlying pipe.
        class pipe_t *pipe;

        //  Pipe writer associated with the other side of the pipe.
        class writer_t *peer;

        //  High and low watermarks for in-memory storage (in bytes).
        uint64_t hwm;
        uint64_t lwm;

        //  Number of messages read so far.
        uint64_t msgs_read;

        //  Endpoint (either session or socket) the pipe is attached to.
        i_endpoint *endpoint;

        reader_t (const reader_t&);
        void operator = (const reader_t&);
    };

    class writer_t : public object_t, public yarray_item_t
    {
    public:

        writer_t (class object_t *parent_,
            uint64_t hwm_, uint64_t lwm_);
        ~writer_t ();

        void set_pipe (class pipe_t *pipe_);
        void set_endpoint (i_endpoint *endpoint_);

        //  Checks whether a message can be written to the pipe.
        //  If writing the message would cause high watermark to be
        //  exceeded, the function returns false.
        bool check_write ();

        //  Writes a message to the underlying pipe. Returns false if the
        //  message cannot be written because high watermark was reached.
        bool write (zmq_msg_t *msg_);

        //  Remove unfinished part of a message from the pipe.
        void rollback ();

        //  Flush the messages downsteam.
        void flush ();

        //  Ask pipe to terminate.
        void term ();

    private:

        void process_reader_info (uint64_t msgs_read_);

        //  Command handlers.
        void process_pipe_term ();

        //  Tests whether the pipe is already full.
        bool pipe_full ();

        //  The underlying pipe.
        class pipe_t *pipe;

        //  Pipe reader associated with the other side of the pipe.
        class reader_t *peer;

        //  High and low watermarks for in-memory storage (in bytes).
        uint64_t hwm;
        uint64_t lwm;

        //  Last confirmed number of messages read from the pipe.
        //  The actual number can be higher.
        uint64_t msgs_read;

        //  Number of messages we have written so far.
        uint64_t msgs_written;

        //  True iff the last attempt to write a message has failed.
        bool stalled;

        //  Endpoint (either session or socket) the pipe is attached to.
        i_endpoint *endpoint;

        writer_t (const writer_t&);
        void operator = (const writer_t&);
    };

    //  Message pipe.
    class pipe_t : public ypipe_t <zmq_msg_t, message_pipe_granularity>
    {
    public:

        pipe_t (object_t *reader_parent_, object_t *writer_parent_,
            uint64_t hwm_);
        ~pipe_t ();

        reader_t reader;
        writer_t writer;

    private:

        uint64_t compute_lwm (uint64_t hwm_);

        pipe_t (const pipe_t&);
        void operator = (const pipe_t&);
    };

}

#endif
