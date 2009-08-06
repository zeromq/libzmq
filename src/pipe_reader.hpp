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

#ifndef __ZMQ_PIPE_READER_HPP_INCLUDED__
#define __ZMQ_PIPE_READER_HPP_INCLUDED__

#include "object.hpp"
#include "stdint.hpp"

namespace zmq
{

    class pipe_reader_t : public object_t
    {
        //  Context is a friend so that it can create & destroy the reader.
        //  By making constructor & destructor private we are sure that nobody
        //  except context messes with readers.
        friend class context_t;

    public:

        //  Set & get index in the associated mux object.
        void set_mux (struct i_mux *mux_);
        void set_index (int index_);
        int get_index ();

        //  Reads a message to the underlying pipe.
        bool read (struct zmq_msg *msg_);

        //  Asks pipe to destroy itself.
        void terminate ();

    private:

        pipe_reader_t (class object_t *parent_, class pipe_t *pipe_,
            uint64_t hwm_, uint64_t lwm_);
        ~pipe_reader_t ();

        //  Second step of reader construction. The parameter cannot be passed
        //  in constructor as peer object doesn't yet exist at the time.
        void set_peer (class object_t *peer_);

        void process_tail (uint64_t bytes_);
        void process_terminate_ack ();

        //  The underlying pipe.
        class pipe_t *pipe;

        //  Pipe writer associated with the other side of the pipe.
        class object_t *peer;

        //  Associated mux object.
        struct i_mux *mux;

        //  Index in the associated mux object.
        int index;

        //  High and low watermarks for in-memory storage (in bytes).
        uint64_t hwm;
        uint64_t lwm;

        //  Positions of head and tail of the pipe (in bytes).
        uint64_t head;
        uint64_t tail;
        uint64_t last_sent_head;

        pipe_reader_t (const pipe_reader_t&);
        void operator = (const pipe_reader_t&);
    };

}

#endif
