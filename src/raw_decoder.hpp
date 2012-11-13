/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2007-2012 Other contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_RAW_DECODER_HPP_INCLUDED__
#define __ZMQ_RAW_DECODER_HPP_INCLUDED__

#include "err.hpp"
#include "msg.hpp"
#include "decoder.hpp"
#include "raw_decoder.hpp"
#include "i_msg_sink.hpp"
#include "stdint.hpp"

namespace zmq
{

    //  Decoder for 0MQ v1 framing protocol. Converts data stream into messages.

    class raw_decoder_t : public decoder_base_t <raw_decoder_t>
    {
    public:

        raw_decoder_t (size_t bufsize_,
            int64_t maxmsgsize_, i_msg_sink *msg_sink_);
        virtual ~raw_decoder_t ();

        //  i_decoder interface.
        virtual void set_msg_sink (i_msg_sink *msg_sink_);

        virtual bool stalled ();

        virtual bool message_ready_size (size_t msg_sz);

    private:


        bool raw_message_ready ();

        i_msg_sink *msg_sink;
        msg_t in_progress;

        const int64_t maxmsgsize;

        raw_decoder_t (const raw_decoder_t&);
        void operator = (const raw_decoder_t&);
    };

}

#endif

