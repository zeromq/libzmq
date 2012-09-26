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

#ifndef __ZMQ_I_ENCODER_HPP_INCLUDED__
#define __ZMQ_I_ENCODER_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{

    //  Forward declaration
    class i_msg_source;

    //  Interface to be implemented by message encoder.

    struct i_encoder
    {
        virtual ~i_encoder () {}

        //  Set message producer.
        virtual void set_msg_source (i_msg_source *msg_source_) = 0;

        //  The function returns a batch of binary data. The data
        //  are filled to a supplied buffer. If no buffer is supplied (data_
        //  is NULL) encoder will provide buffer of its own.
        //  If offset is not NULL, it is filled by offset of the first message
        //  in the batch.If there's no beginning of a message in the batch,
        //  offset is set to -1.
        virtual void get_data (unsigned char **data_, size_t *size_,
            int *offset_ = NULL) = 0;

    };

}

#endif
