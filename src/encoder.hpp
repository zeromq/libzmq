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

#ifndef __ZMQ_ENCODER_HPP_INCLUDED__
#define __ZMQ_ENCODER_HPP_INCLUDED__

#if defined(_MSC_VER)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>

#include "err.hpp"
#include "i_encoder.hpp"
#include "msg.hpp"

namespace zmq
{
//  Helper base class for encoders. It implements the state machine that
//  fills the outgoing buffer. Derived classes should implement individual
//  state machine actions.

template <typename T> class encoder_base_t : public i_encoder
{
  public:
    explicit encoder_base_t (size_t bufsize_) :
        _write_pos (0),
        _to_write (0),
        _next (NULL),
        _new_msg_flag (false),
        _buf_size (bufsize_),
        _buf (static_cast<unsigned char *> (malloc (bufsize_))),
        _in_progress (NULL)
    {
        alloc_assert (_buf);
    }

    ~encoder_base_t () ZMQ_OVERRIDE { free (_buf); }

    //  The function returns a batch of binary data. The data
    //  are filled to a supplied buffer. If no buffer is supplied (data_
    //  points to NULL) decoder object will provide buffer of its own.
    size_t encode (unsigned char **data_, size_t size_) ZMQ_FINAL
    {
        unsigned char *buffer = !*data_ ? _buf : *data_;
        const size_t buffersize = !*data_ ? _buf_size : size_;

        if (in_progress () == NULL)
            return 0;

        size_t pos = 0;
        while (pos < buffersize) {
            //  If there are no more data to return, run the state machine.
            //  If there are still no data, return what we already have
            //  in the buffer.
            if (!_to_write) {
                if (_new_msg_flag) {
                    int rc = _in_progress->close ();
                    errno_assert (rc == 0);
                    rc = _in_progress->init ();
                    errno_assert (rc == 0);
                    _in_progress = NULL;
                    break;
                }
                (static_cast<T *> (this)->*_next) ();
            }

            //  If there are no data in the buffer yet and we are able to
            //  fill whole buffer in a single go, let's use zero-copy.
            //  There's no disadvantage to it as we cannot stuck multiple
            //  messages into the buffer anyway. Note that subsequent
            //  write(s) are non-blocking, thus each single write writes
            //  at most SO_SNDBUF bytes at once not depending on how large
            //  is the chunk returned from here.
            //  As a consequence, large messages being sent won't block
            //  other engines running in the same I/O thread for excessive
            //  amounts of time.
            if (!pos && !*data_ && _to_write >= buffersize) {
                *data_ = _write_pos;
                pos = _to_write;
                _write_pos = NULL;
                _to_write = 0;
                return pos;
            }

            //  Copy data to the buffer. If the buffer is full, return.
            const size_t to_copy = std::min (_to_write, buffersize - pos);
            memcpy (buffer + pos, _write_pos, to_copy);
            pos += to_copy;
            _write_pos += to_copy;
            _to_write -= to_copy;
        }

        *data_ = buffer;
        return pos;
    }

    void load_msg (msg_t *msg_) ZMQ_FINAL
    {
        zmq_assert (in_progress () == NULL);
        _in_progress = msg_;
        (static_cast<T *> (this)->*_next) ();
    }

  protected:
    //  Prototype of state machine action.
    typedef void (T::*step_t) ();

    //  This function should be called from derived class to write the data
    //  to the buffer and schedule next state machine action.
    void next_step (void *write_pos_,
                    size_t to_write_,
                    step_t next_,
                    bool new_msg_flag_)
    {
        _write_pos = static_cast<unsigned char *> (write_pos_);
        _to_write = to_write_;
        _next = next_;
        _new_msg_flag = new_msg_flag_;
    }

    msg_t *in_progress () { return _in_progress; }

  private:
    //  Where to get the data to write from.
    unsigned char *_write_pos;

    //  How much data to write before next step should be executed.
    size_t _to_write;

    //  Next step. If set to NULL, it means that associated data stream
    //  is dead.
    step_t _next;

    bool _new_msg_flag;

    //  The buffer for encoded data.
    const size_t _buf_size;
    unsigned char *const _buf;

    msg_t *_in_progress;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (encoder_base_t)
};
}

#endif
