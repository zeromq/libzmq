/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_ATOMIC_HPP_INCLUDED__
#define __ZMQ_ATOMIC_HPP_INCLUDED__

#include "stdint.hpp"

#if defined ZMQ_FORCE_MUTEXES
#define ZMQ_ATOMIC_MUTEX
#elif (defined __i386__ || defined __x86_64__) && defined __GNUC__
#define ZMQ_ATOMIC_X86
#elif defined ZMQ_HAVE_WINDOWS
#define ZMQ_ATOMIC_WINDOWS
#elif defined ZMQ_HAVE_SOLARIS
#define ZMQ_ATOMIC_SOLARIS
#else
#define ZMQ_ATOMIC_MUTEX
#endif

namespace zmq
{

    //  Atomic assignement.
    inline void atomic_uint32_set (volatile uint32_t *p_, uint32_t value_)
    {
        *p_ = value_;
        //  StoreLoad memory barrier should go here on platforms with
        //  memory models that require it.
    }

    //  Atomic retrieval of an integer.
    inline uint32_t atomic_uint32_get (volatile uint32_t *p_)
    {
        //  StoreLoad memory barrier should go here on platforms with
        //  memory models that require it.
        return *p_;
    }

    //  Atomic addition. Returns the old value.
    inline uint32_t atomic_uint32_add (volatile uint32_t *p_, uint32_t delta_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        return InterlockedExchangeAdd ((LONG*) &value, increment_);
#elif defined ZMQ_ATOMIC_SOLARIS
        return atomic_add_32_nv (&value, increment_) - delta_;
#elif defined ZMQ_ATOMIC_X86
        uint32_t old;
        __asm__ volatile (
            "lock; xadd %0, %1\n\t"
            : "=r" (old), "=m" (*p_)
            : "0" (delta_), "m" (*p_)
            : "cc", "memory");
        return old;
#else
#error // TODO: 
        sync.lock ();
        uint32_t old = *p_;
        *p_ += delta_;
        sync.unlock ();
#endif
    }

    //  Atomic subtraction. Returns the old value.
    inline uint32_t atomic_uint32_sub (volatile uint32_t *p_, uint32_t delta_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        LONG delta = - ((LONG) delta_);
        return InterlockedExchangeAdd ((LONG*) &value, delta);
#elif defined ZMQ_ATOMIC_SOLARIS
        int32_t delta = - ((int32_t) delta_);
        return atomic_add_32_nv (&value, delta) + delta_;
#elif defined ZMQ_ATOMIC_X86
        uint32_t old = -delta_;
        __asm__ volatile ("lock; xaddl %0,%1"
            : "=r" (old), "=m" (*p_)
            : "0" (old), "m" (*p_)
            : "cc");
        return old;
#else
#error // TODO: 
        sync.lock ();
        uint32_t old = *p_;
        *p_ -= delta_;
        sync.unlock ();
        return old;
#endif
    }

    //  Atomic assignement.
    template <typename T>
    inline void atomic_ptr_set (volatile T **p_, T *value_)
    {
        *p_ = value_;
        //  StoreLoad memory barrier should go here on platforms with
        //  memory models that require it.
    }

    //  Perform atomic 'exchange pointers' operation. Old value is returned.
    template <typename T>
    inline void *atomic_ptr_xchg (volatile T **p_, T *value_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        return InterlockedExchangePointer (p_, value_);
#elif defined ZMQ_ATOMIC_SOLARIS
        return atomic_swap_ptr (p_, value_);
#elif defined ZMQ_ATOMIC_X86
        void *old;
        __asm__ volatile (
            "lock; xchg %0, %2"
            : "=r" (old), "=m" (*p_)
            : "m" (*p_), "0" (value_));
        return old;
#else
#error //  TODO:
        sync.lock ();
        void *old = *p_;
        *p_ = value_;
        sync.unlock ();
        return old;
#endif
    }

    //  Perform atomic 'compare and swap' operation on the pointer.
    //  The pointer is compared to 'cmp' argument and if they are
    //  equal, its value is set to 'value'. Old value of the pointer
    //  is returned.
    template <typename T>
    inline void *atomic_ptr_cas (volatile T **p_, T *cmp_, T *value_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        return InterlockedCompareExchangePointer (p_, value_, cmp_);
#elif defined ZMQ_ATOMIC_SOLARIS
        return atomic_cas_ptr (p_, cmp_, value_);
#elif defined ZMQ_ATOMIC_X86
        void *old;
        __asm__ volatile (
            "lock; cmpxchg %2, %3"
            : "=a" (old), "=m" (*p_)
            : "r" (value_), "m" (*p_), "0" (cmp_)
            : "cc");
        return old;
#else
#error //  TODO:
        sync.lock ();
        void *old = *p_;
        if (old == cmp_)
            *p_ = value_;
        sync.unlock ();
        return old;
#endif
    }

#if defined ZMQ_ATOMIC_X86 && defined __x86_64__
    typedef uint64_t atomic_bitmap_t;
#else
    typedef uint32_t atomic_bitmap_t;
#endif

    //  Atomic assignement.
    inline void atomic_bitmap_set (volatile atomic_bitmap_t *p_,
        atomic_bitmap_t value_)
    {
        *p_ = value_;
        //  StoreLoad memory barrier should go here on platforms with
        //  memory models that require it.
    }

    //  Bit-test-set-and-reset. Sets one bit of the value and resets
    //  another one. Returns the original value of the reset bit.
    inline bool atomic_bitmap_btsr (volatile atomic_bitmap_t *p_,
        int set_index_, int reset_index_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        while (true) {
            atomic_bitmap_t oldval = *p_;
            atomic_bitmap_t newval = (oldval | (atomic_bitmap_t (1) <<
                set_index_)) & ~(integer_t (1) << reset_index_);
            if (InterlockedCompareExchange ((volatile LONG*) p_, newval,
                  oldval) == (LONG) oldval)
                return (oldval & (atomic_bitmap_t (1) << reset_index_)) ?
                    true : false; 
        }
#elif defined ZMQ_ATOMIC_SOLARIS
        while (true) {
            atomic_bitmap_t oldval = *p_;
            atomic_bitmap_t newval = (oldval | (atomic_bitmap_t (1) <<
                set_index_)) & ~(integer_t (1) << reset_index_);
            if (atomic_cas_32 (p_, oldval, newval) == oldval)
                return (oldval & (atomic_bitmap_t (1) << reset_index_)) ?
                    true : false; 
        }
#elif defined ZMQ_ATOMIC_X86
        atomic_bitmap_t oldval, dummy;
        __asm__ volatile (
            "mov %0, %1\n\t"
            "1:"
            "mov %1, %2\n\t"
            "bts %3, %2\n\t"
            "btr %4, %2\n\t"
            "lock cmpxchg %2, %0\n\t"
            "jnz 1b\n\t"
            : "+m" (*p_), "=&a" (oldval), "=&r" (dummy)
            : "r" (atomic_bitmap_t (set_index_)),
                "r" (atomic_bitmap_t (reset_index_))
            : "cc");
        return (bool) (oldval & (atomic_bitmap_t (1) << reset_index_)); 
#else
#error // TODO:
        sync.lock ();
        atomic_bitmap_t oldval = *p_;
        *p_ = (oldval | (atomic_bitmap_t (1) << set_index_)) &
            ~(atomic_bitmap_t (1) << reset_index_);
        sync.unlock ();
        return (oldval & (atomic_bitmap_t (1) << reset_index_)) ? true : false;
#endif
    }

    //  Sets value to newval. Returns the original value.
    inline atomic_bitmap_t atomic_bitmap_xchg (volatile atomic_bitmap_t *p_,
        atomic_bitmap_t newval_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        return InterlockedExchange ((volatile LONG*) p_, newval_);
#elif defined ZMQ_ATOMIC_SOLARIS
        return atomic_swap_32 (p_, newval_);
#elif defined ZMQ_ATOMIC_X86
        atomic_bitmap_t oldval = newval_;
        __asm__ volatile (
            "lock; xchg %0, %1"
            : "=r" (oldval)
            : "m" (*p_), "0" (oldval)
            : "memory");
        return oldval; 
#else
#error //  TODO:
        sync.lock ();
        atomic_bitmap_t oldval = *p_;
        *p_ = newval_;
        sync.unlock ();
#endif
    }

    //  izte is "if-zero-then-else" atomic operation - if the value is zero
    //  it substitutes it by 'thenval' else it rewrites it by 'elseval'.
    //  Original value of the integer is returned from this function.
    inline atomic_bitmap_t atomic_bitmap_izte (volatile atomic_bitmap_t *p_,
            atomic_bitmap_t thenval_,  atomic_bitmap_t elseval_)
    {
#if defined ZMQ_ATOMIC_WINDOWS
        while (true) {
            atomic_bitmap_t oldval = *p_;
            atomic_bitmap_t newval = (oldval ? elseval_ : thenval_); 
            if (InterlockedCompareExchange ((volatile LONG*) p_, newval,
                  oldval) == (LONG) oldval)
                return oldval;
        }
#elif defined ZMQ_ATOMIC_SOLARIS
        while (true) {
            atomic_bitmap_t oldval = *p_;
            atomic_bitmap_t newval = (oldval ? elseval_ : thenval_); 
            if (atomic_cas_32 (p_, oldval, newval) == oldval)
                return oldval;
        }
#elif defined ZMQ_ATOMIC_X86
        atomic_bitmap_t oldval;
        atomic_bitmap_t dummy;
        __asm__ volatile (
            "mov %0, %1\n\t"
            "1:"
            "mov %3, %2\n\t"
            "test %1, %1\n\t"
            "jz 2f\n\t"
            "mov %4, %2\n\t"
            "2:"
            "lock cmpxchg %2, %0\n\t"
            "jnz 1b\n\t"
            : "+m" (*p_), "=&a" (oldval), "=&r" (dummy)
            : "r" (thenval_), "r" (elseval_)
            : "cc");
        return oldval;
#else
#error //  TODO:
        sync.lock ();
        atomic_bitmap_t oldval = *p_;
        *p_ = oldval ? elseval_ : thenval_;
        sync.unlock ();
        return oldval;
#endif
    }

}

#endif
