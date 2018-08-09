/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_GENERIC_MTRIE_HPP_INCLUDED__
#define __ZMQ_GENERIC_MTRIE_HPP_INCLUDED__

#include <stddef.h>
#include <set>

#include "stdint.hpp"

namespace zmq
{
//  Multi-trie (prefix tree). Each node in the trie is a set of pointers.
template <typename T> class generic_mtrie_t
{
  public:
    typedef T value_t;
    typedef const unsigned char *prefix_t;

    enum rm_result
    {
        not_found,
        last_value_removed,
        values_remain
    };

    generic_mtrie_t ();
    ~generic_mtrie_t ();

    //  Add key to the trie. Returns true iff no entry with the same prefix_
    //  and size_ existed before.
    bool add (prefix_t prefix_, size_t size_, value_t *value_);

    //  Remove all entries with a specific value from the trie.
    //  The call_on_uniq_ flag controls if the callback is invoked
    //  when there are no entries left on a prefix only (true)
    //  or on every removal (false). The arg_ argument is passed
    //  through to the callback function.
    template <typename Arg>
    void rm (value_t *value_,
             void (*func_) (const unsigned char *data_, size_t size_, Arg arg_),
             Arg arg_,
             bool call_on_uniq_);

    //  Removes a specific entry from the trie.
    //  Returns the result of the operation.
    rm_result rm (prefix_t prefix_, size_t size_, value_t *value_);

    //  Calls a callback function for all matching entries, i.e. any node
    //  corresponding to data_ or a prefix of it. The arg_ argument
    //  is passed through to the callback function.
    template <typename Arg>
    void match (prefix_t data_,
                size_t size_,
                void (*func_) (value_t *value_, Arg arg_),
                Arg arg_);

  private:
    bool add_helper (prefix_t prefix_, size_t size_, value_t *value_);
    template <typename Arg>
    void rm_helper (value_t *value_,
                    unsigned char **buff_,
                    size_t buffsize_,
                    size_t maxbuffsize_,
                    void (*func_) (prefix_t data_, size_t size_, Arg arg_),
                    Arg arg_,
                    bool call_on_uniq_);
    template <typename Arg>
    void rm_helper_multiple_subnodes (unsigned char **buff_,
                                      size_t buffsize_,
                                      size_t maxbuffsize_,
                                      void (*func_) (prefix_t data_,
                                                     size_t size_,
                                                     Arg arg_),
                                      Arg arg_,
                                      bool call_on_uniq_,
                                      value_t *pipe_);

    rm_result rm_helper (prefix_t prefix_, size_t size_, value_t *value_);
    bool is_redundant () const;

    typedef std::set<value_t *> pipes_t;
    pipes_t *_pipes;

    unsigned char _min;
    unsigned short _count;
    unsigned short _live_nodes;
    union
    {
        class generic_mtrie_t<value_t> *node;
        class generic_mtrie_t<value_t> **table;
    } _next;

    generic_mtrie_t (const generic_mtrie_t<value_t> &);
    const generic_mtrie_t<value_t> &
    operator= (const generic_mtrie_t<value_t> &);
};
}

#endif
