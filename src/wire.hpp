/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_WIRE_HPP_INCLUDED__
#define __ZMQ_WIRE_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{
//  Helper functions to convert different integer types to/from network
//  byte order.

inline void put_uint8 (unsigned char *buffer_, uint8_t value_)
{
    *buffer_ = value_;
}

inline uint8_t get_uint8 (const unsigned char *buffer_)
{
    return *buffer_;
}

inline void put_uint16 (unsigned char *buffer_, uint16_t value_)
{
    buffer_[0] = static_cast<unsigned char> (((value_) >> 8) & 0xff);
    buffer_[1] = static_cast<unsigned char> (value_ & 0xff);
}

inline uint16_t get_uint16 (const unsigned char *buffer_)
{
    return ((static_cast<uint16_t> (buffer_[0])) << 8)
           | (static_cast<uint16_t> (buffer_[1]));
}

inline void put_uint32 (unsigned char *buffer_, uint32_t value_)
{
    buffer_[0] = static_cast<unsigned char> (((value_) >> 24) & 0xff);
    buffer_[1] = static_cast<unsigned char> (((value_) >> 16) & 0xff);
    buffer_[2] = static_cast<unsigned char> (((value_) >> 8) & 0xff);
    buffer_[3] = static_cast<unsigned char> (value_ & 0xff);
}

inline uint32_t get_uint32 (const unsigned char *buffer_)
{
    return ((static_cast<uint32_t> (buffer_[0])) << 24)
           | ((static_cast<uint32_t> (buffer_[1])) << 16)
           | ((static_cast<uint32_t> (buffer_[2])) << 8)
           | (static_cast<uint32_t> (buffer_[3]));
}

inline void put_uint64 (unsigned char *buffer_, uint64_t value_)
{
    buffer_[0] = static_cast<unsigned char> (((value_) >> 56) & 0xff);
    buffer_[1] = static_cast<unsigned char> (((value_) >> 48) & 0xff);
    buffer_[2] = static_cast<unsigned char> (((value_) >> 40) & 0xff);
    buffer_[3] = static_cast<unsigned char> (((value_) >> 32) & 0xff);
    buffer_[4] = static_cast<unsigned char> (((value_) >> 24) & 0xff);
    buffer_[5] = static_cast<unsigned char> (((value_) >> 16) & 0xff);
    buffer_[6] = static_cast<unsigned char> (((value_) >> 8) & 0xff);
    buffer_[7] = static_cast<unsigned char> (value_ & 0xff);
}

inline uint64_t get_uint64 (const unsigned char *buffer_)
{
    return ((static_cast<uint64_t> (buffer_[0])) << 56)
           | ((static_cast<uint64_t> (buffer_[1])) << 48)
           | ((static_cast<uint64_t> (buffer_[2])) << 40)
           | ((static_cast<uint64_t> (buffer_[3])) << 32)
           | ((static_cast<uint64_t> (buffer_[4])) << 24)
           | ((static_cast<uint64_t> (buffer_[5])) << 16)
           | ((static_cast<uint64_t> (buffer_[6])) << 8)
           | (static_cast<uint64_t> (buffer_[7]));
}
}

#endif
