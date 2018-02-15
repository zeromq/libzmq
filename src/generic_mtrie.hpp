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
//  Multi-trie. Each node in the trie is a set of pointers to pipes.
template <typename T> class generic_mtrie_t
{
  public:
    typedef T value_t;
    typedef const unsigned char *prefix_t;

    generic_mtrie_t ();
    ~generic_mtrie_t ();

    //  Add key to the trie. Returns true if it's a new subscription
    //  rather than a duplicate.
    bool add (prefix_t prefix_, size_t size_, value_t *pipe_);

    //  Remove all subscriptions for a specific peer from the trie.
    //  The call_on_uniq_ flag controls if the callback is invoked
    //  when there are no subscriptions left on some topics or on
    //  every removal.
    void
    rm (value_t *pipe_,
        void (*func_) (const unsigned char *data_, size_t size_, void *arg_),
        void *arg_,
        bool call_on_uniq_);

    //  Remove specific subscription from the trie. Return true is it was
    //  actually removed rather than de-duplicated.
    bool rm (prefix_t prefix_, size_t size_, value_t *pipe_);

    //  Signal all the matching pipes.
    void match (prefix_t data_,
                size_t size_,
                void (*func_) (value_t *pipe_, void *arg_),
                void *arg_);

  private:
    bool add_helper (prefix_t prefix_, size_t size_, value_t *pipe_);
    void rm_helper (value_t *pipe_,
                    unsigned char **buff_,
                    size_t buffsize_,
                    size_t maxbuffsize_,
                    void (*func_) (prefix_t data_, size_t size_, void *arg_),
                    void *arg_,
                    bool call_on_uniq_);
    bool rm_helper (prefix_t prefix_, size_t size_, value_t *pipe_);
    bool is_redundant () const;

    typedef std::set<value_t *> pipes_t;
    pipes_t *pipes;

    unsigned char min;
    unsigned short count;
    unsigned short live_nodes;
    union
    {
        class generic_mtrie_t<value_t> *node;
        class generic_mtrie_t<value_t> **table;
    } next;

    generic_mtrie_t (const generic_mtrie_t<value_t> &);
    const generic_mtrie_t<value_t> &
    operator= (const generic_mtrie_t<value_t> &);
};
}

#endif
