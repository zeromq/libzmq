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

#ifndef __ZMQ_ATOMIC_BITMAP_HPP_INCLUDED__
#define __ZMQ_ATOMIC_BITMAP_HPP_INCLUDED__

#include "stdint.hpp"
#include "platform.hpp"

//  These are the conditions to choose between different implementations
//  of atomic_bitmap.

#if defined ZMQ_FORCE_MUTEXES
#define ZMQ_ATOMIC_BITMAP_MUTEX
#elif (defined __i386__ || defined __x86_64__) && defined __GNUC__
#define ZMQ_ATOMIC_BITMAP_X86
#elif 0 && defined __sparc__ && defined __GNUC__
#define ZMQ_ATOMIC_BITMAP_SPARC
#elif defined ZMQ_HAVE_WINDOWS
#define ZMQ_ATOMIC_BITMAP_WINDOWS
#elif defined ZMQ_HAVE_SOLARIS
#define ZMQ_ATOMIC_BITMAP_SOLARIS
#else
#define ZMQ_ATOMIC_BITMAP_MUTEX
#endif

#if defined ZMQ_ATOMIC_BITMAP_MUTEX
#include "mutex.hpp"
#elif defined ZMQ_ATOMIC_BITMAP_WINDOWS
#include "windows.hpp"
#elif defined ZMQ_ATOMIC_BITMAP_SOLARIS
#include <atomic.h>
#endif

namespace zmq
{

    //  This class encapuslates several bitwise atomic operations on unsigned
    //  integer. Selection of operations is driven specifically by the needs
    //  of ypollset implementation.

    class atomic_bitmap_t
    {
    public:

#if (defined ZMQ_ATOMIC_BITMAP_X86 || defined ZMQ_FORCE_MUTEXES) \
    && defined __x86_64__
        typedef uint64_t bitmap_t;
#else
        typedef uint32_t bitmap_t;
#endif

        inline atomic_bitmap_t (bitmap_t value_ = 0) :
            value (value_)
        {
        }

        inline ~atomic_bitmap_t ()
        {
        }

        //  Bit-test-set-and-reset. Sets one bit of the value and resets
        //  another one. Returns the original value of the reset bit.
        inline bool btsr (int set_index_, int reset_index_)
        {
#if defined ZMQ_ATOMIC_BITMAP_WINDOWS
            while (true) {
                bitmap_t oldval = value;
                bitmap_t newval = (oldval | (bitmap_t (1) << set_index_)) &
                    ~(bitmap_t (1) << reset_index_);
                if (InterlockedCompareExchange ((volatile LONG*) &value, newval,
                      oldval) == (LONG) oldval)
                    return (oldval & (bitmap_t (1) << reset_index_)) ?
                        true : false;
            }
#elif defined ZMQ_ATOMIC_BITMAP_SOLARIS
            while (true) {
                bitmap_t oldval = value;
                bitmap_t newval = (oldval | (bitmap_t (1) << set_index_)) &
                    ~(bitmap_t (1) << reset_index_);
                if (atomic_cas_32 (&value, oldval, newval) == oldval)
                    return (oldval & (bitmap_t (1) << reset_index_)) ?
                        true : false;
            }
#elif defined ZMQ_ATOMIC_BITMAP_X86
            bitmap_t oldval, dummy;
            __asm__ volatile (
                "mov %0, %1\n\t"
                "1:"
                "mov %1, %2\n\t"
                "bts %3, %2\n\t"
                "btr %4, %2\n\t"
                "lock cmpxchg %2, %0\n\t"
                "jnz 1b\n\t"
                : "+m" (value), "=&a" (oldval), "=&r" (dummy)
                : "r" (bitmap_t(set_index_)), "r" (bitmap_t(reset_index_))
                : "cc");
            return (bool) (oldval & (bitmap_t(1) << reset_index_));
#elif defined ZMQ_ATOMIC_BITMAP_SPARC
            volatile bitmap_t* valptr = &value;
            bitmap_t set_val = bitmap_t(1) << set_index_;
            bitmap_t reset_val = ~(bitmap_t(1) << reset_index_);
            bitmap_t tmp;
            bitmap_t oldval;
            __asm__ volatile(
                "ld       [%5], %2       \n\t"
                "1:                      \n\t"
                "or       %2, %0, %3     \n\t"
                "and      %3, %1, %3     \n\t"
                "cas      [%5], %2, %3   \n\t"
                "cmp      %2, %3         \n\t"
                "bne,a,pn %%icc, 1b      \n\t"
                "mov      %3, %2         \n\t"
                : "+r" (set_val), "+r" (reset_val), "=&r" (tmp),
                  "=&r" (oldval), "+m" (*valptr)
                : "r" (valptr)
                : "cc");
            return oldval;
#elif defined ZMQ_ATOMIC_BITMAP_MUTEX
            sync.lock ();
            bitmap_t oldval = value;
            value = (oldval | (bitmap_t (1) << set_index_)) &
                ~(bitmap_t (1) << reset_index_);
            sync.unlock ();
            return (oldval & (bitmap_t (1) << reset_index_)) ? true : false;
#else
#error
#endif
        }

        //  Sets value to newval. Returns the original value.
        inline bitmap_t xchg (bitmap_t newval_)
        {
            bitmap_t oldval;
#if defined ZMQ_ATOMIC_BITMAP_WINDOWS
            oldval = InterlockedExchange ((volatile LONG*) &value, newval_);
#elif defined ZMQ_ATOMIC_BITMAP_SOLARIS
            oldval = atomic_swap_32 (&value, newval_);
#elif defined ZMQ_ATOMIC_BITMAP_X86
            oldval = newval_;
            __asm__ volatile (
                "lock; xchg %0, %1"
                : "=r" (oldval)
                : "m" (value), "0" (oldval)
                : "memory");
#elif defined ZMQ_ATOMIC_BITMAP_SPARC
            oldval = value;
            volatile bitmap_t* ptrin = &value;
            bitmap_t tmp;
            bitmap_t prev;
            __asm__ __volatile__(
                "ld [%4], %1\n\t"
                "1:\n\t"
                "mov %0, %2\n\t"
                "cas [%4], %1, %2\n\t"
                "cmp %1, %2\n\t"
                "bne,a,pn %%icc, 1b\n\t"
                "mov %2, %1\n\t"
                : "+r" (newval_), "=&r" (tmp), "=&r" (prev), "+m" (*ptrin)
                : "r" (ptrin)
                : "cc");
            return prev;
#elif defined ZMQ_ATOMIC_BITMAP_MUTEX
            sync.lock ();
            oldval = value;
            value = newval_;
            sync.unlock ();
#else
#error
#endif
            return oldval;
        }

        //  izte is "if-zero-then-else" atomic operation - if the value is zero
        //  it substitutes it by 'thenval' else it rewrites it by 'elseval'.
        //  Original value of the integer is returned from this function.
        inline bitmap_t izte (bitmap_t thenval_,
            bitmap_t elseval_)
        {
#if defined ZMQ_ATOMIC_BITMAP_WINDOWS
            while (true) {
                bitmap_t oldval = value;
                bitmap_t newval = oldval == 0 ? thenval_ : elseval_;
                if (InterlockedCompareExchange ((volatile LONG*) &value,
                      newval, oldval) == (LONG) oldval)
                    return oldval;
            }
#elif defined ZMQ_ATOMIC_BITMAP_SOLARIS
            while (true) {
                bitmap_t oldval = value;
                bitmap_t newval = oldval == 0 ? thenval_ : elseval_;
                if (atomic_cas_32 (&value, oldval, newval) == oldval)
                    return oldval;
            }
#elif defined ZMQ_ATOMIC_BITMAP_X86
            bitmap_t oldval;
            bitmap_t dummy;
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
                : "+m" (value), "=&a" (oldval), "=&r" (dummy)
                : "r" (thenval_), "r" (elseval_)
                : "cc");
            return oldval;
#elif defined ZMQ_ATOMIC_BITMAP_SPARC
            volatile bitmap_t* ptrin = &value;
            bitmap_t tmp;
            bitmap_t prev;
            __asm__ __volatile__(
                "ld      [%3], %0       \n\t"
                "mov     0,    %1       \n\t"
                "cas     [%3], %1, %4   \n\t"
                "cmp     %0,   %1       \n\t"
                "be,a,pn %%icc,1f       \n\t"
                "ld      [%3], %0       \n\t"
                "cas     [%3], %0, %5   \n\t"
                "1:                     \n\t"
                : "=&r" (tmp), "=&r" (prev), "+m" (*ptrin)
                : "r" (ptrin), "r" (thenval_), "r" (elseval_)
                : "cc");
            return prev;
#elif defined ZMQ_ATOMIC_BITMAP_MUTEX
            sync.lock ();
            bitmap_t oldval = value;
            value = oldval ? elseval_ : thenval_;
            sync.unlock ();
            return oldval;
#else
#error
#endif
        }

    private:

        volatile bitmap_t value;
#if defined ZMQ_ATOMIC_BITMAP_MUTEX
        mutex_t sync;
#endif

        atomic_bitmap_t (const atomic_bitmap_t&);
        void operator = (const atomic_bitmap_t&);
    };

}

//  Remove macros local to this file.
#if defined ZMQ_ATOMIC_BITMAP_WINDOWS
#undef ZMQ_ATOMIC_BITMAP_WINDOWS
#endif
#if defined ZMQ_ATOMIC_BITMAP_SOLARIS
#undef ZMQ_ATOMIC_BITMAP_SOLARIS
#endif
#if defined ZMQ_ATOMIC_BITMAP_X86
#undef ZMQ_ATOMIC_BITMAP_X86
#endif
#if defined ZMQ_ATOMIC_BITMAP_SPARC
#undef ZMQ_ATOMIC_BITMAP_SPARC
#endif
#if defined ZMQ_ATOMIC_BITMAP_MUTEX
#undef ZMQ_ATOMIC_BITMAP_MUTEX
#endif

#endif
