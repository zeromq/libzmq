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

#ifndef __ZMQ_I_DECODER_HPP_INCLUDED__
#define __ZMQ_I_DECODER_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    class msg_t;

    //  Interface to be implemented by message decoder.

    class i_decoder
    {
    public:
        virtual ~i_decoder () {}

        virtual void get_buffer (unsigned char **data_, size_t *size_) = 0;

        //  Decodes data pointed to by data_.
        //  When a message is decoded, 1 is returned.
        //  When the decoder needs more data, 0 is returnd.
        //  On error, -1 is returned and errno is set accordingly.
        virtual int decode (const unsigned char *data_, size_t size_,
                            size_t &processed) = 0;

        virtual msg_t *msg () = 0;
    };

}

#endif
