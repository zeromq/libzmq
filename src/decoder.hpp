/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZS_DECODER_HPP_INCLUDED__
#define __ZS_DECODER_HPP_INCLUDED__

#include <stddef.h>
#include <string.h>
#include <algorithm>

namespace zs
{

    //  Helper base class for decoders that know the amount of data to read
    //  in advance at any moment. Knowing the amount in advance is a property
    //  of the protocol used. Both AMQP and backend protocol are based on
    //  size-prefixed paradigm, therefore they are using decoder_t to parse
    //  the messages. On the other hand, XML-based transports (like XMPP or
    //  SOAP) don't allow for knowing the size of data to read in advance and
    //  should use different decoding algorithms.
    //
    //  Decoder implements the state machine that parses the incoming buffer.
    //  Derived class should implement individual state machine actions.

    template <typename T> class decoder_t
    {
    public:

        inline decoder_t () :
            read_ptr (NULL),
            to_read (0),
            next (NULL)
        {
        }

        //  Push the binary data to the decoder. Returns number of bytes
        // actually parsed.
        inline size_t write (unsigned char *data_, size_t size_)
        {
            size_t pos = 0;
            while (true) {
                size_t to_copy = std::min (to_read, size_ - pos);
                if (read_ptr) {
                    memcpy (read_ptr, data_ + pos, to_copy);
                    read_ptr += to_copy;
                }
                pos += to_copy;
                to_read -= to_copy;
                while (!to_read)
                    if (!(static_cast <T*> (this)->*next) ())
                        return pos;
                if (pos == size_)
                    return pos;
            }
        }

    protected:

        //  Prototype of state machine action. Action should return false if
        //  it is unable to push the data to the system.
        typedef bool (T::*step_t) ();

        //  This function should be called from derived class to read data
        //  from the buffer and schedule next state machine action.
        inline void next_step (void *read_ptr_, size_t to_read_,
            step_t next_)
        {
            read_ptr = (unsigned char*) read_ptr_;
            to_read = to_read_;
            next = next_;
        }

    private:

        unsigned char *read_ptr;
        size_t to_read;
        step_t next;

        decoder_t (const decoder_t&);
        void operator = (const decoder_t&);
    };

}

#endif
