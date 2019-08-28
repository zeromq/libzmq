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
#include "allocator.hpp"


zmq::allocator_t::allocator_t ()
{
    _type = ZMQ_MSG_ALLOCATOR_DEFAULT;
    _tag = 0xCAFEEBEB;
}

size_t zmq::allocator_t::size () const
{
    switch (_type) {
        case ZMQ_MSG_ALLOCATOR_DEFAULT:
            return 0;

            // using internally a SPSC queue (cannot be used with inproc maybe?) or perhaps an MPMC queue anyway
        case ZMQ_MSG_ALLOCATOR_PER_THREAD_POOL:
            return 0;

            // using internally a MPMC queue
        case ZMQ_MSG_ALLOCATOR_GLOBAL_POOL:
            return _global_pool.size ();

        default:
            return 0;
    }
}


void *zmq::allocator_t::allocate (size_t len)
{
    switch (_type) {
        case ZMQ_MSG_ALLOCATOR_DEFAULT:
            return malloc (len);

            // using internally a SPSC queue (cannot be used with inproc maybe?) or perhaps an MPMC queue anyway
        case ZMQ_MSG_ALLOCATOR_PER_THREAD_POOL:
            // FIXME
            return NULL;

            // using internally a MPMC queue
        case ZMQ_MSG_ALLOCATOR_GLOBAL_POOL:
            return _global_pool.allocate_msg (len);
    }
    return NULL;
}

void zmq::allocator_t::deallocate_msg (void *data_, void *hint_)
{
    allocator_t *alloc = reinterpret_cast<allocator_t *> (hint_);
    switch (alloc->_type) {
        case ZMQ_MSG_ALLOCATOR_DEFAULT:
            free (data_);
            return;

            // using internally a SPSC queue (cannot be used with inproc maybe?) or perhaps an MPMC queue anyway
        case ZMQ_MSG_ALLOCATOR_PER_THREAD_POOL:
            // FIXME
            return;

            // using internally a MPMC queue
        case ZMQ_MSG_ALLOCATOR_GLOBAL_POOL:
            zmq::msg_t::content_t *msg_content =
              (zmq::msg_t::content_t *) data_;
            alloc->_global_pool.deallocate_msg (msg_content, msg_content->size);
    }
}
