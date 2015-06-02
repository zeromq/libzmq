/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_DBUFFER_HPP_INCLUDED__
#define __ZMQ_DBUFFER_HPP_INCLUDED__

#include <stdlib.h>
#include <stddef.h>
#include <algorithm>

#include "mutex.hpp"
#include "msg.hpp"

namespace zmq
{

    //  dbuffer is a single-producer single-consumer double-buffer
    //  implementation.
    //
    //  The producer writes to a back buffer and then tries to swap
    //  pointers between the back and front buffers. If it fails,
    //  due to the consumer reading from the front buffer, it just
    //  gives up, which is ok since writes are many and redundant.
    //
    //  The reader simply reads from the front buffer.
    //
    //  has_msg keeps track of whether there has been a not yet read
    //  value written, it is used by ypipe_conflate to mimic ypipe
    //  functionality regarding a reader being asleep

    template <typename T> class dbuffer_t;

    template <> class dbuffer_t<msg_t>
    {
    public:

        inline dbuffer_t ()
            : back (&storage[0])
            , front (&storage[1])
            , has_msg (false)
        {
            back->init ();
            front->init ();
        }

        inline ~dbuffer_t()
        {
            back->close ();
            front->close ();
        }

        inline void write (const msg_t &value_)
        {
            msg_t& xvalue = const_cast<msg_t&>(value_);

            zmq_assert (xvalue.check ());
            back->move (xvalue);    // cannot just overwrite, might leak

            zmq_assert (back->check ());

            if (sync.try_lock ())
            {
                std::swap (back, front);
                has_msg = true;

                sync.unlock ();
            }
        }

        inline bool read (msg_t *value_)
        {
            if (!value_)
                return false;

            {
                scoped_lock_t lock (sync);
                if (!has_msg)
                    return false;

                zmq_assert (front->check ());

                *value_ = *front;
                front->init ();     // avoid double free

                has_msg = false;
                return true;
            }
        }


        inline bool check_read ()
        {
            scoped_lock_t lock (sync);

            return has_msg;
        }

        inline bool probe (bool (*fn)(const msg_t &))
        {
            scoped_lock_t lock (sync);
            return (*fn) (*front);
        }


    private:
        msg_t storage[2];
        msg_t *back, *front;

        mutex_t sync;
        bool has_msg;

        //  Disable copying of dbuffer.
        dbuffer_t (const dbuffer_t&);
        const dbuffer_t &operator = (const dbuffer_t&);
    };
}

#endif
