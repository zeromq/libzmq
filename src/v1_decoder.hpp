/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_V1_DECODER_HPP_INCLUDED__
#define __ZMQ_V1_DECODER_HPP_INCLUDED__

#include "decoder.hpp"

namespace zmq
{
    //  Decoder for ZMTP/1.0 protocol. Converts data batches into messages.

    class v1_decoder_t : public decoder_base_t <v1_decoder_t>
    {
    public:

        v1_decoder_t (size_t bufsize_, int64_t maxmsgsize_);
        ~v1_decoder_t ();

        virtual msg_t *msg () { return &in_progress; }

    private:

        int one_byte_size_ready ();
        int eight_byte_size_ready ();
        int flags_ready ();
        int message_ready ();

        unsigned char tmpbuf [8];
        msg_t in_progress;

        int64_t maxmsgsize;

        v1_decoder_t (const v1_decoder_t&);
        void operator = (const v1_decoder_t&);
    };

}

#endif

