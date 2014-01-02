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

#include "encoder.hpp"
#include "raw_encoder.hpp"
#include "likely.hpp"
#include "wire.hpp"

zmq::raw_encoder_t::raw_encoder_t (size_t bufsize_) :
    encoder_base_t <raw_encoder_t> (bufsize_)
{
    //  Write 0 bytes to the batch and go to message_ready state.
    next_step (NULL, 0, &raw_encoder_t::raw_message_ready, true);
}

zmq::raw_encoder_t::~raw_encoder_t ()
{
}

void zmq::raw_encoder_t::raw_message_ready ()
{
    next_step (in_progress->data (), in_progress->size (),
        &raw_encoder_t::raw_message_ready, true);
}
