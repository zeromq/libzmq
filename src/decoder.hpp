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

#ifndef __ZMQ_DECODER_HPP_INCLUDED__
#define __ZMQ_DECODER_HPP_INCLUDED__

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>

#include "err.hpp"
#include "msg.hpp"
#include "i_decoder.hpp"
#include "stdint.hpp"

namespace zmq
{
    //  Helper base class for decoders that know the amount of data to read
    //  in advance at any moment. Knowing the amount in advance is a property
    //  of the protocol used. 0MQ framing protocol is based size-prefixed
    //  paradigm, whixh qualifies it to be parsed by this class.
    //  On the other hand, XML-based transports (like XMPP or SOAP) don't allow
    //  for knowing the size of data to read in advance and should use different
    //  decoding algorithms.
    //
    //  This class implements the state machine that parses the incoming buffer.
    //  Derived class should implement individual state machine actions.

    template <typename T> class decoder_base_t : public i_decoder
    {
    public:

        inline decoder_base_t (size_t bufsize_) :
            next (NULL),
            read_pos (NULL),
            to_read (0),
            bufsize (bufsize_)
        {
            buf = (unsigned char*) malloc (bufsize_);
            alloc_assert (buf);
        }

        //  The destructor doesn't have to be virtual. It is mad virtual
        //  just to keep ICC and code checking tools from complaining.
        inline virtual ~decoder_base_t ()
        {
            free (buf);
        }

        //  Returns a buffer to be filled with binary data.
        inline void get_buffer (unsigned char **data_, size_t *size_)
        {
            //  If we are expected to read large message, we'll opt for zero-
            //  copy, i.e. we'll ask caller to fill the data directly to the
            //  message. Note that subsequent read(s) are non-blocking, thus
            //  each single read reads at most SO_RCVBUF bytes at once not
            //  depending on how large is the chunk returned from here.
            //  As a consequence, large messages being received won't block
            //  other engines running in the same I/O thread for excessive
            //  amounts of time.
            if (to_read >= bufsize) {
                *data_ = read_pos;
                *size_ = to_read;
                return;
            }

            *data_ = buf;
            *size_ = bufsize;
        }

        //  Processes the data in the buffer previously allocated using
        //  get_buffer function. size_ argument specifies nemuber of bytes
        //  actually filled into the buffer. Function returns 1 when the
        //  whole message was decoded or 0 when more data is required.
        //  On error, -1 is returned and errno set accordingly.
        //  Number of bytes processed is returned in byts_used_.
        inline int decode (const unsigned char *data_, size_t size_,
                           size_t &bytes_used_)
        {
            bytes_used_ = 0;

            //  In case of zero-copy simply adjust the pointers, no copying
            //  is required. Also, run the state machine in case all the data
            //  were processed.
            if (data_ == read_pos) {
                zmq_assert (size_ <= to_read);
                read_pos += size_;
                to_read -= size_;
                bytes_used_ = size_;

                while (!to_read) {
                    const int rc = (static_cast <T*> (this)->*next) ();
                    if (rc != 0)
                        return rc;
                }
                return 0;
            }

            while (bytes_used_ < size_) {
                //  Copy the data from buffer to the message.
                const size_t to_copy = std::min (to_read, size_ - bytes_used_);
                memcpy (read_pos, data_ + bytes_used_, to_copy);
                read_pos += to_copy;
                to_read -= to_copy;
                bytes_used_ += to_copy;
                //  Try to get more space in the message to fill in.
                //  If none is available, return.
                while (to_read == 0) {
                    const int rc = (static_cast <T*> (this)->*next) ();
                    if (rc != 0)
                        return rc;
                }
            }

            return 0;
        }

    protected:

        //  Prototype of state machine action. Action should return false if
        //  it is unable to push the data to the system.
        typedef int (T::*step_t) ();

        //  This function should be called from derived class to read data
        //  from the buffer and schedule next state machine action.
        inline void next_step (void *read_pos_, size_t to_read_, step_t next_)
        {
            read_pos = (unsigned char*) read_pos_;
            to_read = to_read_;
            next = next_;
        }

    private:

        //  Next step. If set to NULL, it means that associated data stream
        //  is dead. Note that there can be still data in the process in such
        //  case.
        step_t next;

        //  Where to store the read data.
        unsigned char *read_pos;

        //  How much data to read before taking next step.
        size_t to_read;

        //  The duffer for data to decode.
        size_t bufsize;
        unsigned char *buf;

        decoder_base_t (const decoder_base_t&);
        const decoder_base_t &operator = (const decoder_base_t&);
    };
}

#endif

