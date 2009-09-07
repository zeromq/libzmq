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

#ifndef __ZMQ_PIPE_HPP_INCLUDED__
#define __ZMQ_PIPE_HPP_INCLUDED__

#include "../c/zmq.h"

#include "stdint.hpp"
#include "i_endpoint.hpp"
#include "ypipe.hpp"
#include "config.hpp"
#include "object.hpp"

namespace zmq
{

    class reader_t : public object_t
    {
    public:

        reader_t (class object_t *parent_, class pipe_t *pipe_,
            uint64_t hwm_, uint64_t lwm_);
        ~reader_t ();

        void set_endpoint (i_endpoint *endpoint_);

        //  Reads a message to the underlying pipe.
        bool read (struct zmq_msg_t *msg_);

        //  Mnaipulation of index of the pipe.
        void set_index (int index_);
        int get_index ();

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

        //  Positions of head and tail of the pipe (in bytes).
        uint64_t head;
        uint64_t tail;
        uint64_t last_sent_head;

        //  Index of the pipe in the socket's list of inbound pipes.
        int index;

        //  Endpoint (either session or socket) the pipe is attached to.
        i_endpoint *endpoint;

        reader_t (const reader_t&);
        void operator = (const reader_t&);
    };

    class writer_t : public object_t
    {
    public:

        writer_t (class object_t *parent_, class pipe_t *pipe_,
            uint64_t hwm_, uint64_t lwm_);
        ~writer_t ();

        void set_endpoint (i_endpoint *endpoint_);

        //  Checks whether message with specified size can be written to the
        //  pipe. If writing the message would cause high watermark to be
        //  exceeded, the function returns false.
        bool check_write (uint64_t size_);

        //  Writes a message to the underlying pipe. Returns false if the
        //  message cannot be written because high watermark was reached.
        bool write (struct zmq_msg_t *msg_);

        //  Flush the messages downsteam.
        void flush ();

        //  Mnaipulation of index of the pipe.
        void set_index (int index_);
        int get_index ();

        //  Ask pipe to terminate.
        void term ();

    private:

        //  Command handlers.
        void process_pipe_term ();

        //  The underlying pipe.
        class pipe_t *pipe;

        //  Pipe reader associated with the other side of the pipe.
        class reader_t *peer;

        //  High and low watermarks for in-memory storage (in bytes).
        uint64_t hwm;
        uint64_t lwm;

        //  Positions of head and tail of the pipe (in bytes).
        uint64_t head;
        uint64_t tail;

        //  Index of the pipe in the socket's list of outbound pipes.
        int index;

        //  Endpoint (either session or socket) the pipe is attached to.
        i_endpoint *endpoint;

        writer_t (const writer_t&);
        void operator = (const writer_t&);
    };

    //  Message pipe.
    class pipe_t : public ypipe_t <zmq_msg_t, false, message_pipe_granularity>
    {
    public:

        pipe_t (object_t *reader_parent_, object_t *writer_parent_,
            uint64_t hwm_, uint64_t lwm_);
        ~pipe_t ();

        reader_t reader;
        writer_t writer;

    private:

        pipe_t (const pipe_t&);
        void operator = (const pipe_t&);
    };

}

#endif
