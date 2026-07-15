/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SHM_CHANNEL_HPP_INCLUDED__
#define __ZMQ_SHM_CHANNEL_HPP_INCLUDED__

#include "macros.hpp"
#include "shm_ring.hpp"
#include "stdint.hpp"

#include <new>
#include <stddef.h>
#include <string.h>

namespace zmq
{
class shm_channel_t
{
  public:
    static size_t memory_size (uint32_t slot_count_, size_t payload_capacity_)
    {
        const size_t ring_size = shm_ring_t::memory_size (
          slot_count_, sizeof (frame_t) + payload_capacity_);
        return ring_size == 0 ? 0 : cache_line_size + 2 * ring_size;
    }

    static int initialize (void *memory_,
                           size_t memory_size_,
                           uint32_t slot_count_,
                           size_t payload_capacity_)
    {
        const size_t required = memory_size (slot_count_, payload_capacity_);
        if (!memory_ || required == 0 || memory_size_ < required)
            return -1;
        memset (memory_, 0, required);
        header_t *const header = static_cast<header_t *> (memory_);
        header->magic = channel_magic ();
        header->version = 1;
        header->slot_count = slot_count_;
        header->payload_capacity = payload_capacity_;
        header->ring_size =
          shm_ring_t::memory_size (slot_count_,
                                   sizeof (frame_t) + payload_capacity_);
        header->mapping_size = required;

        unsigned char *const base = static_cast<unsigned char *> (memory_);
        if (shm_ring_t::initialize (base + cache_line_size, header->ring_size,
                                    slot_count_,
                                    sizeof (frame_t) + payload_capacity_)
            != 0)
            return -1;
        return shm_ring_t::initialize (
          base + cache_line_size + header->ring_size, header->ring_size,
          slot_count_, sizeof (frame_t) + payload_capacity_);
    }

    shm_channel_t (void *memory_, size_t memory_size_, bool server_) :
        _send (NULL), _receive (NULL), _payload_capacity (0), _valid (false)
    {
        unsigned char *const base = static_cast<unsigned char *> (memory_);
        if (!base || memory_size_ < cache_line_size)
            return;
        const header_t *const header =
          reinterpret_cast<const header_t *> (base);
        if (header->magic != channel_magic () || header->version != 1
            || header->mapping_size != memory_size (
                 header->slot_count, header->payload_capacity)
            || memory_size_ < header->mapping_size)
            return;

        unsigned char *const first = base + cache_line_size;
        unsigned char *const second = first + header->ring_size;
        _send = new (std::nothrow)
          shm_ring_t (server_ ? first : second, header->ring_size);
        _receive = new (std::nothrow)
          shm_ring_t (server_ ? second : first, header->ring_size);
        if (!_send || !_receive || !_send->valid () || !_receive->valid ()) {
            delete _send;
            delete _receive;
            _send = NULL;
            _receive = NULL;
            return;
        }
        _payload_capacity = header->payload_capacity;
        _valid = true;
    }

    ~shm_channel_t ()
    {
        delete _send;
        delete _receive;
    }

    bool valid () const { return _valid; }

    void *try_reserve_send (uint64_t position_,
                            size_t size_,
                            unsigned char flags_)
    {
        if (!_valid || size_ > _payload_capacity)
            return NULL;
        void *const storage = _send->try_acquire_write (position_);
        if (!storage)
            return NULL;
        frame_t *const frame = new (storage) frame_t;
        frame->size = size_;
        frame->flags = flags_;
        return frame + 1;
    }

    void publish_send (uint64_t position_)
    {
        _send->publish_write (position_);
    }

    bool try_receive (uint64_t position_,
                      const void **data_,
                      size_t *size_,
                      unsigned char *flags_) const
    {
        if (!_valid || !data_ || !size_ || !flags_)
            return false;
        const frame_t *const frame = static_cast<const frame_t *> (
          _receive->try_acquire_read (position_));
        if (!frame)
            return false;
        if (frame->size > _payload_capacity)
            return false;
        *data_ = frame + 1;
        *size_ = frame->size;
        *flags_ = frame->flags;
        return true;
    }

    void release_receive (uint64_t position_)
    {
        frame_t *const frame = const_cast<frame_t *> (
          static_cast<const frame_t *> (
            _receive->try_acquire_read (position_)));
        if (frame)
            frame->~frame_t ();
        _receive->release_read (position_);
    }

  private:
    enum
    {
        cache_line_size = 64
    };

    struct frame_t
    {
        size_t size;
        unsigned char flags;
        unsigned char padding[7];
    };

    struct header_t
    {
        uint64_t magic;
        uint32_t version;
        uint32_t slot_count;
        size_t payload_capacity;
        size_t ring_size;
        size_t mapping_size;
    };

    static uint64_t channel_magic ()
    {
        return UINT64_C (0x5a4d5153484d4331);
    }

    shm_ring_t *_send;
    shm_ring_t *_receive;
    size_t _payload_capacity;
    bool _valid;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (shm_channel_t)
};
}

#endif
