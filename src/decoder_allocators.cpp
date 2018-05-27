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

#include "precompiled.hpp"
#include "decoder_allocators.hpp"

#include <cmath>

#include "msg.hpp"

zmq::shared_message_memory_allocator::shared_message_memory_allocator (
  std::size_t bufsize_) :
    _buf (NULL),
    _buf_size (0),
    _max_size (bufsize_),
    _msg_content (NULL),
    _max_counters (static_cast<size_t> (
      std::ceil (static_cast<double> (_max_size)
                 / static_cast<double> (msg_t::max_vsm_size))))
{
}

zmq::shared_message_memory_allocator::shared_message_memory_allocator (
  std::size_t bufsize_, std::size_t max_messages_) :
    _buf (NULL),
    _buf_size (0),
    _max_size (bufsize_),
    _msg_content (NULL),
    _max_counters (max_messages_)
{
}

zmq::shared_message_memory_allocator::~shared_message_memory_allocator ()
{
    deallocate ();
}

unsigned char *zmq::shared_message_memory_allocator::allocate ()
{
    if (_buf) {
        // release reference count to couple lifetime to messages
        zmq::atomic_counter_t *c =
          reinterpret_cast<zmq::atomic_counter_t *> (_buf);

        // if refcnt drops to 0, there are no message using the buffer
        // because either all messages have been closed or only vsm-messages
        // were created
        if (c->sub (1)) {
            // buffer is still in use as message data. "Release" it and create a new one
            // release pointer because we are going to create a new buffer
            release ();
        }
    }

    // if buf != NULL it is not used by any message so we can re-use it for the next run
    if (!_buf) {
        // allocate memory for reference counters together with reception buffer
        std::size_t const allocationsize =
          _max_size + sizeof (zmq::atomic_counter_t)
          + _max_counters * sizeof (zmq::msg_t::content_t);

        _buf = static_cast<unsigned char *> (std::malloc (allocationsize));
        alloc_assert (_buf);

        new (_buf) atomic_counter_t (1);
    } else {
        // release reference count to couple lifetime to messages
        zmq::atomic_counter_t *c =
          reinterpret_cast<zmq::atomic_counter_t *> (_buf);
        c->set (1);
    }

    _buf_size = _max_size;
    _msg_content = reinterpret_cast<zmq::msg_t::content_t *> (
      _buf + sizeof (atomic_counter_t) + _max_size);
    return _buf + sizeof (zmq::atomic_counter_t);
}

void zmq::shared_message_memory_allocator::deallocate ()
{
    zmq::atomic_counter_t *c = reinterpret_cast<zmq::atomic_counter_t *> (_buf);
    if (_buf && !c->sub (1)) {
        std::free (_buf);
    }
    clear ();
}

unsigned char *zmq::shared_message_memory_allocator::release ()
{
    unsigned char *b = _buf;
    clear ();
    return b;
}

void zmq::shared_message_memory_allocator::clear ()
{
    _buf = NULL;
    _buf_size = 0;
    _msg_content = NULL;
}

void zmq::shared_message_memory_allocator::inc_ref ()
{
    (reinterpret_cast<zmq::atomic_counter_t *> (_buf))->add (1);
}

void zmq::shared_message_memory_allocator::call_dec_ref (void *, void *hint_)
{
    zmq_assert (hint_);
    unsigned char *buf = static_cast<unsigned char *> (hint_);
    zmq::atomic_counter_t *c = reinterpret_cast<zmq::atomic_counter_t *> (buf);

    if (!c->sub (1)) {
        c->~atomic_counter_t ();
        std::free (buf);
        buf = NULL;
    }
}


std::size_t zmq::shared_message_memory_allocator::size () const
{
    return _buf_size;
}

unsigned char *zmq::shared_message_memory_allocator::data ()
{
    return _buf + sizeof (zmq::atomic_counter_t);
}
