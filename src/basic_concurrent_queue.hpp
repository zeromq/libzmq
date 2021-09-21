/*
    Copyright (c) 2019-2020 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_BASIC_CONCURRENT_QUEUE_INCLUDED__
#define __ZMQ_BASIC_CONCURRENT_QUEUE_INCLUDED__

#include <queue>

#include "mutex.hpp"

namespace zmq
{
template <typename T> class basic_concurrent_queue_t
{
  public:
    basic_concurrent_queue_t () : _queue_mutex (new mutex_t) {}
    ~basic_concurrent_queue_t () { delete _queue_mutex; }
    void enqueue (T item)
    {
        _queue_mutex->lock ();
        _queue.push (item);
        _queue_mutex->unlock ();
    }

    bool try_dequeue (T &item)
    {
        bool success = false;
        _queue_mutex->lock ();
        if (!_queue.empty ()) {
            item = _queue.front ();
            _queue.pop ();
            success = true;
        }
        _queue_mutex->unlock ();
        return success;
    }

    size_t size_approx () const { return _queue.size (); }

  private:
    std::queue<T> _queue;
    mutex_t *_queue_mutex;
};
}
#endif
