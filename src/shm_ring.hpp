/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SHM_RING_HPP_INCLUDED__
#define __ZMQ_SHM_RING_HPP_INCLUDED__

#include "stdint.hpp"

#include <stddef.h>
#include <string.h>

namespace zmq
{
class shm_ring_t
{
  public:
    static size_t memory_size (uint32_t slot_count_, size_t slot_size_)
    {
        if (slot_count_ < 2 || slot_size_ == 0)
            return 0;
        return cache_line_size
               + static_cast<size_t> (slot_count_)
                   * slot_stride (slot_size_);
    }

    static int initialize (void *memory_,
                           size_t memory_size_,
                           uint32_t slot_count_,
                           size_t slot_size_)
    {
        const size_t required = memory_size (slot_count_, slot_size_);
        if (!memory_ || required == 0 || memory_size_ < required)
            return -1;

        memset (memory_, 0, required);
        header_t *const header = static_cast<header_t *> (memory_);
        header->magic = ring_magic ();
        header->version = 1;
        header->slot_count = slot_count_;
        header->slot_size = slot_size_;
        header->stride = slot_stride (slot_size_);
        header->mapping_size = required;

        unsigned char *const base = static_cast<unsigned char *> (memory_);
        for (uint32_t i = 0; i != slot_count_; ++i) {
            slot_control_t *const control = reinterpret_cast<slot_control_t *> (
              base + cache_line_size + header->stride * i);
            atomic_store (&control->sequence, i, __ATOMIC_RELAXED);
        }
        return 0;
    }

    shm_ring_t (void *memory_, size_t memory_size_) :
        _base (static_cast<unsigned char *> (memory_)), _header (NULL),
        _valid (false)
    {
        if (!_base || memory_size_ < cache_line_size)
            return;
        header_t *const header = reinterpret_cast<header_t *> (_base);
        if (header->magic != ring_magic () || header->version != 1
            || header->slot_count < 2 || header->slot_size == 0
            || header->stride != slot_stride (header->slot_size)
            || header->mapping_size
                 != memory_size (header->slot_count, header->slot_size)
            || memory_size_ < header->mapping_size)
            return;
        _header = header;
        _valid = true;
    }

    bool valid () const { return _valid; }

    void *try_acquire_write (uint64_t position_)
    {
        if (!_valid)
            return NULL;
        slot_control_t *const control = slot (position_);
        if (atomic_load (&control->sequence, __ATOMIC_ACQUIRE) != position_)
            return NULL;
        return reinterpret_cast<unsigned char *> (control) + cache_line_size;
    }

    void publish_write (uint64_t position_)
    {
        slot_control_t *const control = slot (position_);
        atomic_store (&control->sequence, position_ + 1, __ATOMIC_RELEASE);
    }

    const void *try_acquire_read (uint64_t position_) const
    {
        if (!_valid)
            return NULL;
        slot_control_t *const control = slot (position_);
        if (atomic_load (&control->sequence, __ATOMIC_ACQUIRE)
            != position_ + 1)
            return NULL;
        return reinterpret_cast<unsigned char *> (control) + cache_line_size;
    }

    void release_read (uint64_t position_)
    {
        slot_control_t *const control = slot (position_);
        atomic_store (&control->sequence,
                      position_ + _header->slot_count, __ATOMIC_RELEASE);
    }

  private:
    enum
    {
        cache_line_size = 64
    };

    struct header_t
    {
        uint64_t magic;
        uint32_t version;
        uint32_t slot_count;
        size_t slot_size;
        size_t stride;
        size_t mapping_size;
    };

    struct slot_control_t
    {
        volatile uint64_t sequence;
        unsigned char padding[cache_line_size - sizeof (uint64_t)];
    };

    static uint64_t ring_magic () { return UINT64_C (0x5a4d5153484d5231); }

    static size_t align_up (size_t value_)
    {
        return (value_ + cache_line_size - 1) & ~(cache_line_size - 1);
    }

    static size_t slot_stride (size_t slot_size_)
    {
        return cache_line_size + align_up (slot_size_);
    }

    static uint64_t atomic_load (const volatile uint64_t *value_, int order_)
    {
        return __atomic_load_n (value_, order_);
    }

    static void atomic_store (volatile uint64_t *value_,
                              uint64_t value,
                              int order_)
    {
        __atomic_store_n (value_, value, order_);
    }

    slot_control_t *slot (uint64_t position_) const
    {
        return reinterpret_cast<slot_control_t *> (
          _base + cache_line_size
          + _header->stride * (position_ % _header->slot_count));
    }

    unsigned char *_base;
    header_t *_header;
    bool _valid;
};
}

#endif
