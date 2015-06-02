/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_TRIE_HPP_INCLUDED__
#define __ZMQ_TRIE_HPP_INCLUDED__

#include <stddef.h>

#include "stdint.hpp"

namespace zmq
{

    class trie_t
    {
    public:

        trie_t ();
        ~trie_t ();

        //  Add key to the trie. Returns true if this is a new item in the trie
        //  rather than a duplicate.
        bool add (unsigned char *prefix_, size_t size_);

        //  Remove key from the trie. Returns true if the item is actually
        //  removed from the trie.
        bool rm (unsigned char *prefix_, size_t size_);

        //  Check whether particular key is in the trie.
        bool check (unsigned char *data_, size_t size_);

        //  Apply the function supplied to each subscription in the trie.
        void apply (void (*func_) (unsigned char *data_, size_t size_,
            void *arg_), void *arg_);

    private:

        void apply_helper (
            unsigned char **buff_, size_t buffsize_, size_t maxbuffsize_,
            void (*func_) (unsigned char *data_, size_t size_, void *arg_),
            void *arg_);
        bool is_redundant () const;

        uint32_t refcnt;
        unsigned char min;
        unsigned short count;
        unsigned short live_nodes;
        union {
            class trie_t *node;
            class trie_t **table;
        } next;

        trie_t (const trie_t&);
        const trie_t &operator = (const trie_t&);
    };

}

#endif

