/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include "random.hpp"
#include "uuid.hpp"
#include "err.hpp"

//  Here we can use different ways of generating random data, as avialable
//  on different platforms. At the moment, we'll assume the UUID is random
//  enough to use for that purpose.
void zmq::generate_random (void *buf_, size_t size_)
{
    //  Collapsing an UUID into 4 bytes.
    zmq_assert (size_ == 4);
    uint32_t buff [4];
    generate_uuid ((void*) buff);
    uint32_t result = buff [0];
    result ^= buff [1];
    result ^= buff [2];
    result ^= buff [3];
    *((uint32_t*) buf_) = result;
}
