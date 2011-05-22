/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_PIPE_HPP_INCLUDED__
#define __ZMQ_PIPE_HPP_INCLUDED__

#include "msg.hpp"
#include "ypipe.hpp"
#include "config.hpp"
#include "object.hpp"
#include "array.hpp"

namespace zmq
{

    //  Create a pipepair for bi-directional transfer of messages.
    //  First HWM is for messages passed from first pipe to the second pipe.
    //  Second HWM is for messages passed from second pipe to the first pipe.
    //  Delay specifies whether the pipe receives all the pending messages
    //  before terminating or whether it terminates straight away.
    int pipepair (class object_t *parents_ [2], class pipe_t* pipes_ [2],
        int hwms_ [2], bool delays_ [2]);

    struct i_pipe_events
    {
        virtual ~i_pipe_events () {}

        virtual void read_activated (class pipe_t *pipe_) = 0;
        virtual void write_activated (class pipe_t *pipe_) = 0;
        virtual void terminated (class pipe_t *pipe_) = 0;
    };

    class pipe_t :
        public object_t,
        public array_item_t
    {
        //  This allows pipepair to create pipe objects.
        friend int pipepair (class object_t *parents_ [2],
            class pipe_t* pipes_ [2], int hwms_ [2], bool delays_ [2]);

    public:

        //  Specifies the object to send events to.
        void set_event_sink (i_pipe_events *sink_);

        //  Returns true if there is at least one message to read in the pipe.
        bool check_read ();

        //  Reads a message to the underlying pipe.
        bool read (msg_t *msg_);

        //  Checks whether messages can be written to the pipe. If writing
        //  the message would cause high watermark the function returns false.
        bool check_write (msg_t *msg_);

        //  Writes a message to the underlying pipe. Returns false if the
        //  message cannot be written because high watermark was reached.
        bool write (msg_t *msg_);

        //  Remove unfinished parts of the outbound message from the pipe.
        void rollback ();

        //  Flush the messages downsteam.
        void flush ();

        //  Ask pipe to terminate. The termination will happen asynchronously
        //  and user will be notified about actual deallocation by 'terminated'
        //  event.
        void terminate ();

    private:

        //  Command handlers.
        void process_activate_read ();
        void process_activate_write (uint64_t msgs_read_);
        void process_pipe_term ();
        void process_pipe_term_ack ();

        //  Type of the underlying lock-free pipe.
        typedef ypipe_t <msg_t, message_pipe_granularity> upipe_t;

        //  Constructor is private. Pipe can only be created using
        //  pipepair function.
        pipe_t (object_t *parent_, upipe_t *inpipe_, upipe_t *outpipe_,
            int inhwm_, int outhwm_, bool delay_);

        //  Pipepair uses this function to let us know about
        //  the peer pipe object.
        void set_peer (pipe_t *pipe_);

        //  Destructor is private. Pipe objects destroy themselves.
        ~pipe_t ();

        //  Underlying pipes for both directions.
        upipe_t *inpipe;
        upipe_t *outpipe;

        //  Can the pipe be read from / written to?
        bool in_active;
        bool out_active;

        //  High watermark for the outbound pipe.
        int hwm;

        //  Low watermark for the inbound pipe.
        int lwm;

        //  Number of messages read and written so far.
        uint64_t msgs_read;
        uint64_t msgs_written;

        //  Last received peer's msgs_read. The actual number in the peer
        //  can be higher at the moment.
        uint64_t peers_msgs_read;

        //  The pipe object on the other side of the pipepair.
        pipe_t *peer;

        //  Sink to send events to.
        i_pipe_events *sink;

        //  True is 'terminate' method was called or termination request
        //  was received from the peer.
        bool terminating;

        //  True is we've already got pipe_term command from the peer.
        bool term_recvd;

        //  True if delimiter was already received from the peer.
        bool delimited;

        //  If true, we receive all the pending inbound messages before
        //  terminating. If false, we terminate immediately when the peer
        //  asks us to.
        bool delay;

        //  Returns true if the message is delimiter; false otherwise.
        static bool is_delimiter (msg_t &msg_);

        //  Computes appropriate low watermark from the given high watermark.
        static int compute_lwm (int hwm_);

        //  Disable copying.
        pipe_t (const pipe_t&);
        const pipe_t &operator = (const pipe_t&);
    };

}

#endif
