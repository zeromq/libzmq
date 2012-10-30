/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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

#ifndef __ZMQ_RAW_ENCODER_HPP_INCLUDED__
#define __ZMQ_RAW_ENCODER_HPP_INCLUDED__

#if defined(_MSC_VER)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>

#include "err.hpp"
#include "msg.hpp"
#include "i_encoder.hpp"

namespace zmq
{

    //  Encoder for 0MQ framing protocol. Converts messages into data batches.

    class raw_encoder_t : public encoder_base_t <raw_encoder_t>
    {
    public:

        raw_encoder_t (size_t bufsize_, i_msg_source *msg_source_);
        ~raw_encoder_t ();

        void set_msg_source (i_msg_source *msg_source_);

    private:

        bool raw_message_ready ();
        bool raw_message_size_ready ();

        i_msg_source *msg_source;
        msg_t in_progress;
        unsigned char tmpbuf [4];
        raw_encoder_t (const raw_encoder_t&);
        const raw_encoder_t &operator = (const raw_encoder_t&);
    };
}

#endif

