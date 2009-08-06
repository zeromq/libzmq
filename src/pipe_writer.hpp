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

#ifndef __ZMQ_PIPE_WRITER_HPP_INCLUDED__
#define __ZMQ_PIPE_WRITER_HPP_INCLUDED__

#include "object.hpp"
#include "stdint.hpp"

namespace zmq
{

    class pipe_writer_t : public object_t
    {
        //  Context is a friend so that it can create & destroy the writer.
        //  By making constructor & destructor private we are sure that nobody
        //  except context messes with writers.
        friend class context_t;

    public:

        //  Set & get index in the associated demux object.
        void set_demux (struct i_demux *demux_);
        void set_index (int index_);
        int get_index ();

        //  Writes a message to the underlying pipe. Returns false if the
        //  message cannot be written to the pipe at the moment.
        bool write (struct zmq_msg *msg_);

        //  Flush the messages downsteam.
        void flush ();

        //  Asks pipe to destroy itself.
        void terminate ();

    private:

        pipe_writer_t (class object_t *parent_, class pipe_t *pipe_,
            class object_t *peer_, uint64_t hwm_, uint64_t lwm_);
        ~pipe_writer_t ();

        void process_head (uint64_t bytes_);
        void process_terminate ();

        //  The underlying pipe.
        class pipe_t *pipe;

        //  Pipe reader associated with the other side of the pipe.
        class object_t *peer;

        //  Associated demux object.
        struct i_demux *demux;

        //  Index in the associated demux object.
        int index;

        //  High and low watermarks for in-memory storage (in bytes).
        uint64_t hwm;
        uint64_t lwm;

        //  Positions of head and tail of the pipe (in bytes).
        uint64_t head;
        uint64_t tail;

        pipe_writer_t (const pipe_writer_t&);
        void operator = (const pipe_writer_t&);
    };

}

#endif
