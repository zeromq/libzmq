/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_ATOMIC_PTR_HPP_INCLUDED__
#define __ZMQ_ATOMIC_PTR_HPP_INCLUDED__

#include "macros.hpp"

#if defined ZMQ_FORCE_MUTEXES
#define ZMQ_ATOMIC_PTR_MUTEX
#elif (defined __cplusplus && __cplusplus >= 201103L)                          \
  || (defined _MSC_VER && _MSC_VER >= 1900)
#define ZMQ_ATOMIC_PTR_CXX11
#elif defined ZMQ_HAVE_ATOMIC_INTRINSICS
#define ZMQ_ATOMIC_PTR_INTRINSIC
#elif (defined __i386__ || defined __x86_64__) && defined __GNUC__
#define ZMQ_ATOMIC_PTR_X86
#elif defined __ARM_ARCH_7A__ && defined __GNUC__
#define ZMQ_ATOMIC_PTR_ARM
#elif defined __tile__
#define ZMQ_ATOMIC_PTR_TILE
#elif defined ZMQ_HAVE_WINDOWS
#define ZMQ_ATOMIC_PTR_WINDOWS
#elif (defined ZMQ_HAVE_SOLARIS || defined ZMQ_HAVE_NETBSD                     \
       || defined ZMQ_HAVE_GNU)
#define ZMQ_ATOMIC_PTR_ATOMIC_H
#else
#define ZMQ_ATOMIC_PTR_MUTEX
#endif

#if defined ZMQ_ATOMIC_PTR_MUTEX
#include "mutex.hpp"
#elif defined ZMQ_ATOMIC_PTR_CXX11
#include <atomic>
#elif defined ZMQ_ATOMIC_PTR_WINDOWS
#include "windows.hpp"
#elif defined ZMQ_ATOMIC_PTR_ATOMIC_H
#include <atomic.h>
#elif defined ZMQ_ATOMIC_PTR_TILE
#include <arch/atomic.h>
#endif

namespace zmq
{
#if !defined ZMQ_ATOMIC_PTR_CXX11
inline void *atomic_xchg_ptr (void **ptr_,
                              void *const val_
#if defined ZMQ_ATOMIC_PTR_MUTEX
                              ,
                              mutex_t &_sync
#endif
                              ) ZMQ_NOEXCEPT
{
#if defined ZMQ_ATOMIC_PTR_WINDOWS
    return InterlockedExchangePointer ((PVOID *) ptr_, val_);
#elif defined ZMQ_ATOMIC_PTR_INTRINSIC
    return __atomic_exchange_n (ptr_, val_, __ATOMIC_ACQ_REL);
#elif defined ZMQ_ATOMIC_PTR_ATOMIC_H
    return atomic_swap_ptr (ptr_, val_);
#elif defined ZMQ_ATOMIC_PTR_TILE
    return arch_atomic_exchange (ptr_, val_);
#elif defined ZMQ_ATOMIC_PTR_X86
    void *old;
    __asm__ volatile ("lock; xchg %0, %2"
                      : "=r"(old), "=m"(*ptr_)
                      : "m"(*ptr_), "0"(val_));
    return old;
#elif defined ZMQ_ATOMIC_PTR_ARM
    void *old;
    unsigned int flag;
    __asm__ volatile ("       dmb     sy\n\t"
                      "1:     ldrex   %1, [%3]\n\t"
                      "       strex   %0, %4, [%3]\n\t"
                      "       teq     %0, #0\n\t"
                      "       bne     1b\n\t"
                      "       dmb     sy\n\t"
                      : "=&r"(flag), "=&r"(old), "+Qo"(*ptr_)
                      : "r"(ptr_), "r"(val_)
                      : "cc");
    return old;
#elif defined ZMQ_ATOMIC_PTR_MUTEX
    _sync.lock ();
    void *old = *ptr_;
    *ptr_ = val_;
    _sync.unlock ();
    return old;
#else
#error atomic_ptr is not implemented for this platform
#endif
}

inline void *atomic_cas (void *volatile *ptr_,
                         void *cmp_,
                         void *val_
#if defined ZMQ_ATOMIC_PTR_MUTEX
                         ,
                         mutex_t &_sync
#endif
                         ) ZMQ_NOEXCEPT
{
#if defined ZMQ_ATOMIC_PTR_WINDOWS
    return InterlockedCompareExchangePointer ((volatile PVOID *) ptr_, val_,
                                              cmp_);
#elif defined ZMQ_ATOMIC_PTR_INTRINSIC
    void *old = cmp_;
    __atomic_compare_exchange_n (ptr_, &old, val_, false, __ATOMIC_RELEASE,
                                 __ATOMIC_ACQUIRE);
    return old;
#elif defined ZMQ_ATOMIC_PTR_ATOMIC_H
    return atomic_cas_ptr (ptr_, cmp_, val_);
#elif defined ZMQ_ATOMIC_PTR_TILE
    return arch_atomic_val_compare_and_exchange (ptr_, cmp_, val_);
#elif defined ZMQ_ATOMIC_PTR_X86
    void *old;
    __asm__ volatile ("lock; cmpxchg %2, %3"
                      : "=a"(old), "=m"(*ptr_)
                      : "r"(val_), "m"(*ptr_), "0"(cmp_)
                      : "cc");
    return old;
#elif defined ZMQ_ATOMIC_PTR_ARM
    void *old;
    unsigned int flag;
    __asm__ volatile ("       dmb     sy\n\t"
                      "1:     ldrex   %1, [%3]\n\t"
                      "       mov     %0, #0\n\t"
                      "       teq     %1, %4\n\t"
                      "       it      eq\n\t"
                      "       strexeq %0, %5, [%3]\n\t"
                      "       teq     %0, #0\n\t"
                      "       bne     1b\n\t"
                      "       dmb     sy\n\t"
                      : "=&r"(flag), "=&r"(old), "+Qo"(*ptr_)
                      : "r"(ptr_), "r"(cmp_), "r"(val_)
                      : "cc");
    return old;
#elif defined ZMQ_ATOMIC_PTR_MUTEX
    _sync.lock ();
    void *old = *ptr_;
    if (*ptr_ == cmp_)
        *ptr_ = val_;
    _sync.unlock ();
    return old;
#else
#error atomic_ptr is not implemented for this platform
#endif
}
#endif

//  This class encapsulates several atomic operations on pointers.

template <typename T> class atomic_ptr_t
{
  public:
    //  Initialise atomic pointer
    atomic_ptr_t () ZMQ_NOEXCEPT { _ptr = NULL; }

    //  Set value of atomic pointer in a non-threadsafe way
    //  Use this function only when you are sure that at most one
    //  thread is accessing the pointer at the moment.
    void set (T *ptr_) ZMQ_NOEXCEPT { _ptr = ptr_; }

    //  Perform atomic 'exchange pointers' operation. Pointer is set
    //  to the 'val_' value. Old value is returned.
    T *xchg (T *val_) ZMQ_NOEXCEPT
    {
#if defined ZMQ_ATOMIC_PTR_CXX11
        return _ptr.exchange (val_, std::memory_order_acq_rel);
#else
        return (T *) atomic_xchg_ptr ((void **) &_ptr, val_
#if defined ZMQ_ATOMIC_PTR_MUTEX
                                      ,
                                      _sync
#endif
        );
#endif
    }

    //  Perform atomic 'compare and swap' operation on the pointer.
    //  The pointer is compared to 'cmp' argument and if they are
    //  equal, its value is set to 'val_'. Old value of the pointer
    //  is returned.
    T *cas (T *cmp_, T *val_) ZMQ_NOEXCEPT
    {
#if defined ZMQ_ATOMIC_PTR_CXX11
        _ptr.compare_exchange_strong (cmp_, val_, std::memory_order_acq_rel);
        return cmp_;
#else
        return (T *) atomic_cas ((void **) &_ptr, cmp_, val_
#if defined ZMQ_ATOMIC_PTR_MUTEX
                                 ,
                                 _sync
#endif
        );
#endif
    }

  private:
#if defined ZMQ_ATOMIC_PTR_CXX11
    std::atomic<T *> _ptr;
#else
    volatile T *_ptr;
#endif

#if defined ZMQ_ATOMIC_PTR_MUTEX
    mutex_t _sync;
#endif

#if !defined ZMQ_ATOMIC_PTR_CXX11
    ZMQ_NON_COPYABLE_NOR_MOVABLE (atomic_ptr_t)
#endif
};

struct atomic_value_t
{
    atomic_value_t (const int value_) ZMQ_NOEXCEPT : _value (value_) {}

    atomic_value_t (const atomic_value_t &src_) ZMQ_NOEXCEPT
        : _value (src_.load ())
    {
    }

    void store (const int value_) ZMQ_NOEXCEPT
    {
#if defined ZMQ_ATOMIC_PTR_CXX11
        _value.store (value_, std::memory_order_release);
#else
        atomic_xchg_ptr ((void **) &_value, (void *) (ptrdiff_t) value_
#if defined ZMQ_ATOMIC_PTR_MUTEX
                         ,
                         _sync
#endif
        );
#endif
    }

    int load () const ZMQ_NOEXCEPT
    {
#if defined ZMQ_ATOMIC_PTR_CXX11
        return _value.load (std::memory_order_acquire);
#else
        return (int) (ptrdiff_t) atomic_cas ((void **) &_value, 0, 0
#if defined ZMQ_ATOMIC_PTR_MUTEX
                                             ,
#if defined __SUNPRO_CC
                                             const_cast<mutex_t &> (_sync)
#else
                                             _sync
#endif
#endif
        );
#endif
    }

  private:
#if defined ZMQ_ATOMIC_PTR_CXX11
    std::atomic<int> _value;
#else
    volatile ptrdiff_t _value;
#endif

#if defined ZMQ_ATOMIC_PTR_MUTEX
    mutable mutex_t _sync;
#endif

  private:
    atomic_value_t &operator= (const atomic_value_t &src_);
};
}

//  Remove macros local to this file.
#undef ZMQ_ATOMIC_PTR_MUTEX
#undef ZMQ_ATOMIC_PTR_INTRINSIC
#undef ZMQ_ATOMIC_PTR_CXX11
#undef ZMQ_ATOMIC_PTR_X86
#undef ZMQ_ATOMIC_PTR_ARM
#undef ZMQ_ATOMIC_PTR_TILE
#undef ZMQ_ATOMIC_PTR_WINDOWS
#undef ZMQ_ATOMIC_PTR_ATOMIC_H

#endif
