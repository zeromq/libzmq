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

#ifndef __ZMQ_BLOB_HPP_INCLUDED__
#define __ZMQ_BLOB_HPP_INCLUDED__

#include "macros.hpp"
#include "err.hpp"

#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <ios>

#if __cplusplus >= 201103L || defined(_MSC_VER) && _MSC_VER > 1700
#define ZMQ_HAS_MOVE_SEMANTICS
#define ZMQ_MAP_INSERT_OR_EMPLACE(k, v) emplace (k, v)
#define ZMQ_PUSH_OR_EMPLACE_BACK emplace_back
#define ZMQ_MOVE(x) std::move (x)
#else
#if defined __SUNPRO_CC
template <typename K, typename V>
std::pair<const K, V> make_pair_fix_const (const K &k, const V &v)
{
    return std::pair<const K, V> (k, v);
}

#define ZMQ_MAP_INSERT_OR_EMPLACE(k, v) insert (make_pair_fix_const (k, v))
#else
#define ZMQ_MAP_INSERT_OR_EMPLACE(k, v) insert (std::make_pair (k, v))
#endif

#define ZMQ_PUSH_OR_EMPLACE_BACK push_back
#define ZMQ_MOVE(x) (x)
#endif

namespace zmq
{
struct reference_tag_t
{
};

//  Object to hold dynamically allocated opaque binary data.
//  On modern compilers, it will be movable but not copyable. Copies
//  must be explicitly created by set_deep_copy.
//  On older compilers, it is copyable for syntactical reasons.
struct blob_t
{
    //  Creates an empty blob_t.
    blob_t () : _data (0), _size (0), _owned (true) {}

    //  Creates a blob_t of a given size, with uninitialized content.
    explicit blob_t (const size_t size_) :
        _data (static_cast<unsigned char *> (malloc (size_))),
        _size (size_),
        _owned (true)
    {
        alloc_assert (_data);
    }

    //  Creates a blob_t of a given size, an initializes content by copying
    // from another buffer.
    blob_t (const unsigned char *const data_, const size_t size_) :
        _data (static_cast<unsigned char *> (malloc (size_))),
        _size (size_),
        _owned (true)
    {
        alloc_assert (_data);
        memcpy (_data, data_, size_);
    }

    //  Creates a blob_t for temporary use that only references a
    //  pre-allocated block of data.
    //  Use with caution and ensure that the blob_t will not outlive
    //  the referenced data.
    blob_t (unsigned char *const data_, const size_t size_, reference_tag_t) :
        _data (data_),
        _size (size_),
        _owned (false)
    {
    }

    //  Returns the size of the blob_t.
    size_t size () const { return _size; }

    //  Returns a pointer to the data of the blob_t.
    const unsigned char *data () const { return _data; }

    //  Returns a pointer to the data of the blob_t.
    unsigned char *data () { return _data; }

    //  Defines an order relationship on blob_t.
    bool operator< (blob_t const &other_) const
    {
        const int cmpres =
          memcmp (_data, other_._data, std::min (_size, other_._size));
        return cmpres < 0 || (cmpres == 0 && _size < other_._size);
    }

    //  Sets a blob_t to a deep copy of another blob_t.
    void set_deep_copy (blob_t const &other_)
    {
        clear ();
        _data = static_cast<unsigned char *> (malloc (other_._size));
        alloc_assert (_data);
        _size = other_._size;
        _owned = true;
        memcpy (_data, other_._data, _size);
    }

    //  Sets a blob_t to a copy of a given buffer.
    void set (const unsigned char *const data_, const size_t size_)
    {
        clear ();
        _data = static_cast<unsigned char *> (malloc (size_));
        alloc_assert (_data);
        _size = size_;
        _owned = true;
        memcpy (_data, data_, size_);
    }

    //  Empties a blob_t.
    void clear ()
    {
        if (_owned) {
            free (_data);
        }
        _data = 0;
        _size = 0;
    }

    ~blob_t ()
    {
        if (_owned) {
            free (_data);
        }
    }

#ifdef ZMQ_HAS_MOVE_SEMANTICS
    blob_t (const blob_t &) = delete;
    blob_t &operator= (const blob_t &) = delete;

    blob_t (blob_t &&other_) ZMQ_NOEXCEPT : _data (other_._data),
                                            _size (other_._size),
                                            _owned (other_._owned)
    {
        other_._owned = false;
    }
    blob_t &operator= (blob_t &&other_) ZMQ_NOEXCEPT
    {
        if (this != &other_) {
            clear ();
            _data = other_._data;
            _size = other_._size;
            _owned = other_._owned;
            other_._owned = false;
        }
        return *this;
    }
#else
    blob_t (const blob_t &other) : _owned (false) { set_deep_copy (other); }
    blob_t &operator= (const blob_t &other)
    {
        if (this != &other) {
            clear ();
            set_deep_copy (other);
        }
        return *this;
    }
#endif

  private:
    unsigned char *_data;
    size_t _size;
    bool _owned;
};
}

#endif
