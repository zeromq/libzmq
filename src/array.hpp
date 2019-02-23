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

#ifndef __ZMQ_ARRAY_INCLUDED__
#define __ZMQ_ARRAY_INCLUDED__

#include <vector>
#include <algorithm>

namespace zmq
{
//  Implementation of fast arrays with O(1) access, insertion and
//  removal. The array stores pointers rather than objects.
//  O(1) is achieved by making items inheriting from
//  array_item_t<ID> class which internally stores the position
//  in the array.
//  The ID template argument is used to differentiate among arrays
//  and thus let an object be stored in different arrays.

//  Base class for objects stored in the array. If you want to store
//  same object in multiple arrays, each of those arrays has to have
//  different ID. The item itself has to be derived from instantiations of
//  array_item_t template for all relevant IDs.

template <int ID = 0> class array_item_t
{
  public:
    inline array_item_t () : _array_index (-1) {}

    //  The destructor doesn't have to be virtual. It is made virtual
    //  just to keep ICC and code checking tools from complaining.
    inline virtual ~array_item_t () {}

    inline void set_array_index (int index_) { _array_index = index_; }

    inline int get_array_index () { return _array_index; }

  private:
    int _array_index;

    array_item_t (const array_item_t &);
    const array_item_t &operator= (const array_item_t &);
};


template <typename T, int ID = 0> class array_t
{
  private:
    typedef array_item_t<ID> item_t;

  public:
    typedef typename std::vector<T *>::size_type size_type;

    inline array_t () {}

    inline ~array_t () {}

    inline size_type size () { return _items.size (); }

    inline bool empty () { return _items.empty (); }

    inline T *&operator[] (size_type index_) { return _items[index_]; }

    inline void push_back (T *item_)
    {
        if (item_)
            ((item_t *) item_)->set_array_index ((int) _items.size ());
        _items.push_back (item_);
    }

    inline void erase (T *item_)
    {
        erase (((item_t *) item_)->get_array_index ());
    }

    inline void erase (size_type index_)
    {
        if (_items.back ())
            ((item_t *) _items.back ())->set_array_index ((int) index_);
        _items[index_] = _items.back ();
        _items.pop_back ();
    }

    inline void swap (size_type index1_, size_type index2_)
    {
        if (_items[index1_])
            ((item_t *) _items[index1_])->set_array_index ((int) index2_);
        if (_items[index2_])
            ((item_t *) _items[index2_])->set_array_index ((int) index1_);
        std::swap (_items[index1_], _items[index2_]);
    }

    inline void clear () { _items.clear (); }

    inline size_type index (T *item_)
    {
        return (size_type) ((item_t *) item_)->get_array_index ();
    }

  private:
    typedef std::vector<T *> items_t;
    items_t _items;

    array_t (const array_t &);
    const array_t &operator= (const array_t &);
};
}

#endif
