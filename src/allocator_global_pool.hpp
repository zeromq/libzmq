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

#ifndef __ZMQ_MEMORYPOOL_HPP_INCLUDED__
#define __ZMQ_MEMORYPOOL_HPP_INCLUDED__

#include "allocator_base.hpp"
#include <vector>
#include "msg.hpp"

#if (defined __cplusplus && __cplusplus >= 201103L)
#include "../external/mpmcqueue/concurrentqueue.h"
#else
#include "basic_concurrent_queue.hpp"
#endif
#include "mutex.hpp"

#define ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE (256)

namespace zmq
{
class allocator_global_pool_t : public allocator_base_t
{
  public:
    allocator_global_pool_t (size_t initialMaximumBlockSize = 8192);
    ~allocator_global_pool_t ();

    void allocate_block (size_t bl);

    // TODO have a look if realloc is possible, probably not as not thread safe as messages might still be in-flight?
    void expand_block (size_t bl);

    void *allocate (size_t len) final; // consumer thread: user app thread

    void
    deallocate (void *data_) final; // producer thread: ZMQ background IO thread

    size_t size () const;

  private:
    typedef struct
    {
        size_t num_msgs;
        // actual user data
        std::vector<uint8_t *> raw_data;
    } msg_block_t;

    std::vector<msg_block_t> _storage;
#if (defined __cplusplus && __cplusplus >= 201103L)
    std::vector<moodycamel::ConcurrentQueue<uint8_t *> > _free_list;
#else
    std::vector<basic_concurrent_queue_t<uint8_t *> > _free_list;
#endif
    mutex_t _storage_mutex;

    inline size_t MsgBlockToBytes (size_t block)
    {
        return ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE * 2 ^ block;
    }

    // by Todd Lehman https://stackoverflow.com/questions/994593/how-to-do-an-integer-log2-in-c
    inline int uint64_log2 (uint64_t n)
    {
#define S(k)                                                                   \
    if (n >= (UINT64_C (1) << k)) {                                            \
        i += k;                                                                \
        n >>= k;                                                               \
    }
        assert (n != 0);
        int i = 0;
        S (32);
        S (16);
        S (8);
        S (4);
        S (2);
        S (1);
        return i;

#undef S
    }
    inline size_t BytesToMsgBlock (size_t n)
    {
        if (n <= ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE) {
            return 0;
        }
        return uint64_log2 (n / ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE);
    }
};
}

#endif
