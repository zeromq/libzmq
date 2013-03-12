/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_MTRIE_HPP_INCLUDED__
#define __ZMQ_MTRIE_HPP_INCLUDED__

#include <stddef.h>
#include <set>

#include "stdint.hpp"

namespace zmq
{

    class pipe_t;

    //  Multi-trie. Each node in the trie is a set of pointers to pipes.

    class mtrie_t
    {
    public:

        mtrie_t ();
        ~mtrie_t ();

        //  Add key to the trie. Returns true if it's a new subscription
        //  rather than a duplicate.
        bool add (unsigned char *prefix_, size_t size_, zmq::pipe_t *pipe_);

        //  Remove all subscriptions for a specific peer from the trie.
        //  If there are no subscriptions left on some topics, invoke the
        //  supplied callback function.
        void rm (zmq::pipe_t *pipe_,
            void (*func_) (unsigned char *data_, size_t size_, void *arg_),
            void *arg_);

        //  Remove specific subscription from the trie. Return true is it was
        //  actually removed rather than de-duplicated.
        bool rm (unsigned char *prefix_, size_t size_, zmq::pipe_t *pipe_);

        //  Signal all the matching pipes.
        void match (unsigned char *data_, size_t size_,
            void (*func_) (zmq::pipe_t *pipe_, void *arg_), void *arg_);

    private:

        bool add_helper (unsigned char *prefix_, size_t size_,
            zmq::pipe_t *pipe_);
        void rm_helper (zmq::pipe_t *pipe_, unsigned char **buff_,
            size_t buffsize_, size_t maxbuffsize_,
            void (*func_) (unsigned char *data_, size_t size_, void *arg_),
            void *arg_);
        bool rm_helper (unsigned char *prefix_, size_t size_,
            zmq::pipe_t *pipe_);
        bool is_redundant () const;

        typedef std::set <zmq::pipe_t*> pipes_t;
        pipes_t *pipes;

        unsigned char min;
        unsigned short count;
        unsigned short live_nodes;
        union {
            class mtrie_t *node;
            class mtrie_t **table;
        } next;

        mtrie_t (const mtrie_t&);
        const mtrie_t &operator = (const mtrie_t&);
    };

}

#endif

