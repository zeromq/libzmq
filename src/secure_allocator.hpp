/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SECURE_ALLOCATOR_HPP_INCLUDED__
#define __ZMQ_SECURE_ALLOCATOR_HPP_INCLUDED__

#include "platform.hpp"
#include "macros.hpp"

#ifdef ZMQ_HAVE_CURVE

#if defined(ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

#include <memory>

namespace zmq
{
#if defined(ZMQ_USE_LIBSODIUM)
template <class T> struct secure_allocator_t
{
    typedef T value_type;

    secure_allocator_t () ZMQ_DEFAULT;

    template <class U>
    secure_allocator_t (const secure_allocator_t<U> &) ZMQ_NOEXCEPT
    {
    }
    T *allocate (std::size_t n) ZMQ_NOEXCEPT
    {
        T *res = static_cast<T *> (sodium_allocarray (sizeof (T), n));
        alloc_assert (res);
        return res;
    }
    void deallocate (T *p, std::size_t) ZMQ_NOEXCEPT
    {
        if (p)
            sodium_free (p);
    }

    // the following is only required with C++98
    // TODO maybe make this conditionally compiled
    typedef T *pointer;
    typedef const T *const_pointer;
    typedef T &reference;
    typedef const T &const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;
    template <class U> struct rebind
    {
        typedef secure_allocator_t<U> other;
    };

    void construct (pointer p, const_reference val)
    {
        new ((void *) p) value_type (val);
    }
    void destroy (pointer p) { p->~value_type (); }
    size_type max_size () const { return SIZE_MAX; }
};
template <class T, class U>
bool operator== (const secure_allocator_t<T> &, const secure_allocator_t<U> &)
{
    return true;
}
template <class T, class U>
bool operator!= (const secure_allocator_t<T> &, const secure_allocator_t<U> &)
{
    return false;
}
#else
template <typename T> struct secure_allocator_t : std::allocator<T>
{
    secure_allocator_t () ZMQ_DEFAULT;

    template <class U>
    secure_allocator_t (const secure_allocator_t<U> &) ZMQ_NOEXCEPT
    {
    }

    template <class U> struct rebind
    {
        typedef secure_allocator_t<U> other;
    };
};
#endif
}

#endif

#endif
