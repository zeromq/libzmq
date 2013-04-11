/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_V2_ENCODER_HPP_INCLUDED__
#define __ZMQ_V2_ENCODER_HPP_INCLUDED__

#include "encoder.hpp"

namespace zmq
{
    //  Encoder for 0MQ framing protocol. Converts messages into data stream.

    class v2_encoder_t : public encoder_base_t <v2_encoder_t>
    {
    public:

        v2_encoder_t (size_t bufsize_);
        virtual ~v2_encoder_t ();

    private:

        void size_ready ();
        void message_ready ();

        unsigned char tmpbuf [9];

        v2_encoder_t (const v2_encoder_t&);
        const v2_encoder_t &operator = (const v2_encoder_t&);
    };
}

#endif

