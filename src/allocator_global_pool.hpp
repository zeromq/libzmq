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
#include "concurrentqueue.h"

// FIXME: we need to grow dynamically the mempool
#define MAX_ACTIVE_MESSAGES (16384)

#define ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE 256

namespace zmq
{
class global_memory_pool_t
{
    typedef struct
    {
        size_t num_msgs;
        // actual user data
        uint8_t *raw_data;
    } msg_block_t;

    typedef enum
    {
        MsgBlock_SizeClass_256 = 0, // for messages up to 256B long
        MsgBlock_SizeClass_512,
        MsgBlock_SizeClass_1024,
        MsgBlock_SizeClass_2048,
        MsgBlock_SizeClass_4096,
        MsgBlock_SizeClass_8192,

        MsgBlock_NumSizeClasses
    } MsgBlock_e;

    inline size_t MsgBlockToBytes (size_t block)
    {
        return ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE * 2 ^ block;
    }

    inline size_t BytesToMsgBlock (size_t n)
    {
        return (size_t) floor (log2 (n)
                               - log2 (ZMQ_GLOBAL_POOL_FIRST_BLOCK_SIZE));
    }

  public:
    global_memory_pool_t (size_t initialMaximumBlockSize = 8092)
    {
        allocate_block (BytesToMsgBlock (initialMaximumBlockSize));
    }

    ~global_memory_pool_t ()
    {
        // deallocate all message classes
        for (int i = 0; i < MsgBlock_NumSizeClasses; i++) {
            free (m_storage[i].raw_data);
            m_storage[i].raw_data = NULL;
        }
    }

    void allocate_block (size_t bl)
    {
        size_t maxBlock = m_storage.size () - 1;
        if (maxBlock < bl) {
            m_storage.resize (bl + 1);
            m_free_list.resize (bl + 1);
            for (auto i = maxBlock; i < bl; i++) {
                size_t msg_size = MsgBlockToBytes (i);
                m_storage[i].num_msgs = MAX_ACTIVE_MESSAGES;
                m_storage[i].raw_data =
                  (uint8_t *) malloc (MAX_ACTIVE_MESSAGES * msg_size);

                uint8_t *msg_memory = m_storage[i].raw_data;
                for (int j = 0; j < MAX_ACTIVE_MESSAGES; j++) {
                    m_free_list[i].enqueue (msg_memory);
                    msg_memory += msg_size;
                }
            }
        }
    }

    void *allocate_msg (size_t len) // consumer thread: user app thread
    {
        size_t bl = BytesToMsgBlock (len);

        if (m_storage.size () <= bl) {
            allocate_block (bl);
        }

        // consume 1 block from the list of free msg
        uint8_t *next_avail = nullptr;
        if (!m_free_list[bl].try_dequeue (next_avail)) {
            assert (0); // I want to find out if this ever happens
            return NULL;
        }

        assert (next_avail);
        return next_avail;
    }

    void
    deallocate_msg (void *data_,
                    size_t len) // producer thread: ZMQ background IO thread
    {
        size_t bl = BytesToMsgBlock (len);

        // produce a new free msg:
        m_free_list[bl].enqueue ((uint8_t *) data_);
    }

    size_t size () const
    {
        size_t acc = 0;
        for (int i = 0; i < MsgBlock_NumSizeClasses; i++)
            acc += m_free_list[i].size_approx ();
        return acc;
    }

  private:
    std::vector<msg_block_t> m_storage;
    std::vector<moodycamel::ConcurrentQueue<uint8_t *> > m_free_list;
};

class allocator_global_pool_t : public allocator_base_t
{
  public:
    // allocate() typically gets called by the consumer thread: the user app thread(s)
    void *allocate (size_t len) final;

    // deallocate_msg() typically gets called by the producer thread: the ZMQ background IO thread(s)
    void deallocate (void *data_) final;

    size_t size () const;

  private:
    global_memory_pool_t _global_pool;
};
}

#endif
