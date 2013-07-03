/*
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

#ifndef __ZMQ_I_DECODER_HPP_INCLUDED__
#define __ZMQ_I_DECODER_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    // Forward declaration
    struct i_msg_sink;

    //  Interface to be implemented by message decoder.

    struct i_decoder
    {
        virtual ~i_decoder () {}

        virtual void set_msg_sink (i_msg_sink *msg_sink_) = 0;

        virtual void get_buffer (unsigned char **data_, size_t *size_) = 0;

        virtual size_t process_buffer (unsigned char *data_, size_t size_) = 0;

        virtual bool stalled () = 0;

    };

}

#endif
