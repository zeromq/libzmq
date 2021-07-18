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

#ifndef __ZMQ_I_ALLOCATOR_HPP_INCLUDED__
#define __ZMQ_I_ALLOCATOR_HPP_INCLUDED__

namespace zmq
{
class allocator_default_t
{
  public:
    allocator_default_t ();

    ~allocator_default_t ();

    static void *allocate_fn (void *allocator_, size_t len_)
    {
        return static_cast<allocator_default_t *> (allocator_)->allocate (len_);
    }

    static void deallocate_fn (void *allocator_, void *data_)
    {
        return static_cast<allocator_default_t *> (allocator_)
          ->deallocate (data_);
    }

    static bool check_tag_fn (void *allocator_)
    {
        return static_cast<allocator_default_t *> (allocator_)->check_tag ();
    }

    static void destroy_fn (void *allocator_)
    {
        operator delete (static_cast<allocator_default_t *> (allocator_));
    }

    // allocate() typically gets called by the consumer thread: the user app thread(s)
    void *allocate (size_t len_);

    void deallocate (void *data_);

    bool check_tag () const;

  private:
    //  Used to check whether the object is a socket.
    uint32_t _tag;
};
}

#endif
