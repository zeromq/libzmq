/* SPDX-License-Identifier: MPL-2.0 */

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
    dbuffer_t () : _back (&_storage[0]), _front (&_storage[1]), _has_msg (false)
    {
        _back->init ();
        _front->init ();
    }

    ~dbuffer_t ()
    {
        _back->close ();
        _front->close ();
    }

    void write (const msg_t &value_)
    {
        zmq_assert (value_.check ());
        *_back = value_;

        zmq_assert (_back->check ());

        if (_sync.try_lock ()) {
            _front->move (*_back);
            _has_msg = true;

            _sync.unlock ();
        }
    }

    bool read (msg_t *value_)
    {
        if (!value_)
            return false;

        {
            scoped_lock_t lock (_sync);
            if (!_has_msg)
                return false;

            zmq_assert (_front->check ());

            *value_ = *_front;
            _front->init (); // avoid double free

            _has_msg = false;
            return true;
        }
    }


    bool check_read ()
    {
        scoped_lock_t lock (_sync);

        return _has_msg;
    }

    bool probe (bool (*fn_) (const msg_t &))
    {
        scoped_lock_t lock (_sync);
        return (*fn_) (*_front);
    }


  private:
    msg_t _storage[2];
    msg_t *_back, *_front;

    mutex_t _sync;
    bool _has_msg;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (dbuffer_t)
};
}

#endif
