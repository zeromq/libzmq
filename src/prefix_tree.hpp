/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_PREFIX_TREE_HPP_INCLUDED__
#define __ZMQ_PREFIX_TREE_HPP_INCLUDED__

#include <stddef.h>

#include "stdint.hpp"

namespace zmq
{

    class prefix_tree_t
    {
    public:

        prefix_tree_t ();
        ~prefix_tree_t ();

        void add (unsigned char *prefix_, size_t size_);
        bool rm (unsigned char *prefix_, size_t size_);
        bool check (unsigned char *data_, size_t size_);

    private:

        uint32_t refcnt;
        unsigned char min;
        unsigned char count;
        union {
            class prefix_tree_t *node;
            class prefix_tree_t **table;
        } next;
    };

}

#endif

