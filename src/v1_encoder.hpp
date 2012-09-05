/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2012 iMatix Corporation
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

#ifndef __ZMQ_V1_ENCODER_HPP_INCLUDED__
#define __ZMQ_V1_ENCODER_HPP_INCLUDED__

#include "msg.hpp"
#include "i_msg_source.hpp"
#include "encoder.hpp"

namespace zmq
{

    class i_msg_source;

    //  Encoder for 0MQ framing protocol. Converts messages into data stream.

    class v1_encoder_t : public encoder_base_t <v1_encoder_t>
    {
    public:

        v1_encoder_t (size_t bufsize_, i_msg_source *msg_source_);
        virtual ~v1_encoder_t ();

        virtual void set_msg_source (i_msg_source *msg_source_);

    private:

        bool size_ready ();
        bool message_ready ();

        i_msg_source *msg_source;
        msg_t in_progress;
        unsigned char tmpbuf [9];

        v1_encoder_t (const v1_encoder_t&);
        const v1_encoder_t &operator = (const v1_encoder_t&);
    };
}

#endif

