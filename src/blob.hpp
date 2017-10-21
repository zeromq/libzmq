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

#include <stdlib.h>
#include <string.h>
#include <algorithm>

#if __cplusplus >= 201103L || defined(_MSC_VER) && _MSC_VER >= 1700
#define ZMQ_HAS_MOVE_SEMANTICS
#define ZMQ_MAP_INSERT_OR_EMPLACE(k, v) emplace (k,v)
#define ZMQ_PUSH_OR_EMPLACE_BACK emplace_back
#define ZMQ_MOVE(x) std::move (x)
#else
#define ZMQ_MAP_INSERT_OR_EMPLACE(k, v) insert (std::make_pair (k, v))
#define ZMQ_PUSH_OR_EMPLACE_BACK push_back
#define ZMQ_MOVE(x) (x)
#endif

namespace zmq
{
    struct reference_tag_t {};

    //  Object to hold dynamically allocated opaque binary data.
    //  On modern compilers, it will be movable but not copyable. Copies 
    //  must be explicitly created by set_deep_copy.
    //  On older compilers, it is copyable for syntactical reasons.
    struct blob_t
    {
        //  Creates an empty blob_t.
        blob_t () : data_ (0), size_ (0), owned_ (true) {}

        //  Creates a blob_t of a given size, with uninitialized content.
        blob_t (const size_t size)
            : data_ ((unsigned char*)malloc (size))
            , size_ (size)
            , owned_ (true)
        {
        }

        //  Creates a blob_t of a given size, an initializes content by copying 
        // from another buffer.
        blob_t(const unsigned char * const data, const size_t size)
            : data_ ((unsigned char*)malloc (size))
            , size_ (size)
            , owned_ (true)
        {
            memcpy(data_, data, size_);
        }

        //  Creates a blob_t for temporary use that only references a 
        //  pre-allocated block of data.
        //  Use with caution and ensure that the blob_t will not outlive
        //  the referenced data.
        blob_t (unsigned char * const data, const size_t size, reference_tag_t)
            : data_ (data)
            , size_ (size)
            , owned_ (false)
        {
        }

        //  Returns the size of the blob_t.
        size_t size () const { return size_;  }
        
        //  Returns a pointer to the data of the blob_t.
        const unsigned char *data() const {
            return data_;
        }

        //  Returns a pointer to the data of the blob_t.
        unsigned char *data() {
            return data_;
        }

        //  Defines an order relationship on blob_t.
        bool operator< (blob_t const &other) const {
            int cmpres = memcmp (data_, other.data_, std::min (size_, other.size_));
            return cmpres < 0 || (cmpres == 0 && size_ < other.size_);
        }

        //  Sets a blob_t to a deep copy of another blob_t.
        void set_deep_copy (blob_t const &other)
        {               
            clear ();
            data_ = (unsigned char*)malloc (other.size_);
            size_ = other.size_;
            owned_ = true;
            memcpy (data_, other.data_, size_);
        }

        //  Sets a blob_t to a copy of a given buffer.
        void set (const unsigned char * const data, const size_t size)
        {
            clear ();
            data_ = (unsigned char*)malloc (size);
            size_ = size;
            owned_ = true;
            memcpy (data_, data, size_);
        }

        //  Empties a blob_t.
        void clear () {
            if (owned_) { free (data_); }
            data_ = 0; size_ = 0;
        }

        ~blob_t () {            
            if (owned_) { free (data_);  }
        }

#ifdef ZMQ_HAS_MOVE_SEMANTICS
        blob_t (const blob_t &) = delete;
        blob_t &operator= (const blob_t &) = delete;
        
        blob_t (blob_t&& other) 
            : data_ (other.data_)
            , size_ (other.size_)
            , owned_ (other.owned_)
        {
            other.owned_ = false;
        }
        blob_t &operator= (blob_t&& other) {
            if (this != &other)
            {
                clear ();
                data_ = other.data_;
                size_ = other.size_;
                owned_ = other.owned_;
                other.owned_ = false;
            }
            return *this;
        }
#else
        blob_t (const blob_t &other) 
            : owned_(false)
        {
            set_deep_copy (other);
        }
        blob_t &operator= (const blob_t &other) {
            if (this != &other)
            {
                clear ();
                set_deep_copy (other);
            }
            return *this;
        }
#endif

    private:
        unsigned char *data_;
        size_t size_;
        bool owned_;
    };

}

#endif

