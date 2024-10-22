/* SPDX-License-Identifier: MPL-2.0 */

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
        alloc_assert (!_size || _data);
    }

    //  Creates a blob_t of a given size, an initializes content by copying
    // from another buffer.
    blob_t (const unsigned char *const data_, const size_t size_) :
        _data (static_cast<unsigned char *> (malloc (size_))),
        _size (size_),
        _owned (true)
    {
        alloc_assert (!size_ || _data);
        if (size_ && _data) {
            memcpy (_data, data_, size_);
        }
    }

    //  Creates a blob_t for temporary use that only references a
    //  pre-allocated block of data.
    //  Use with caution and ensure that the blob_t will not outlive
    //  the referenced data.
    blob_t (unsigned char *const data_, const size_t size_, reference_tag_t) :
        _data (data_), _size (size_), _owned (false)
    {
    }

    //  Returns the size of the blob_t.
    size_t size () const { return _size; }

    //  Returns a pointer to the data of the blob_t.
    const unsigned char *data () const { return _data; }

    //  Returns a pointer to the data of the blob_t.
    unsigned char *data () { return _data; }

    //  Defines an order relationship on blob_t.
    bool operator<(blob_t const &other_) const
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
        alloc_assert (!other_._size || _data);
        _size = other_._size;
        _owned = true;
        if (_size && _data) {
            memcpy (_data, other_._data, _size);
        }
    }

    //  Sets a blob_t to a copy of a given buffer.
    void set (const unsigned char *const data_, const size_t size_)
    {
        clear ();
        _data = static_cast<unsigned char *> (malloc (size_));
        alloc_assert (!size_ || _data);
        _size = size_;
        _owned = true;
        if (size_ && _data) {
            memcpy (_data, data_, size_);
        }
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
    blob_t (const blob_t &other) : _owned (false)
    {
        set_deep_copy (other);
    }
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
