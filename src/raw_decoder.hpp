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

#ifndef __ZMQ_RAW_DECODER_HPP_INCLUDED__
#define __ZMQ_RAW_DECODER_HPP_INCLUDED__

#include "err.hpp"
#include "msg.hpp"
#include "i_decoder.hpp"
#include "stdint.hpp"

namespace zmq
{

    //  Decoder for 0MQ v1 framing protocol. Converts data stream into messages.

    class raw_decoder_t : public i_decoder
    {
    public:

        raw_decoder_t (size_t bufsize_);
        virtual ~raw_decoder_t ();

        //  i_decoder interface.

        virtual void get_buffer (unsigned char **data_, size_t *size_);

        virtual int decode (const unsigned char *data_, size_t size_,
                            size_t &processed);

        virtual msg_t *msg () { return &in_progress; }


    private:


        msg_t in_progress;

        const size_t bufsize;

        unsigned char *buffer;

        raw_decoder_t (const raw_decoder_t&);
        void operator = (const raw_decoder_t&);
    };

}

#endif

