/*
    Copyright (c) 2007-2011 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include <stdlib.h>

#include <new>
#include <algorithm>

#include "platform.hpp"
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "err.hpp"
#include "pipe.hpp"
#include "mtrie.hpp"

zmq::mtrie_t::mtrie_t () :
    min (0),
    count (0)
{
}

zmq::mtrie_t::~mtrie_t ()
{
    if (count == 1)
        delete next.node;
    else if (count > 1) {
        for (unsigned short i = 0; i != count; ++i)
            if (next.table [i])
                delete next.table [i];
        free (next.table);
    }
}

bool zmq::mtrie_t::add (unsigned char *prefix_, size_t size_, pipe_t *pipe_)
{
    //  We are at the node corresponding to the prefix. We are done.
    if (!size_) {
        bool result = pipes.empty ();
        pipes.insert (pipe_);
        return result;
    }

    unsigned char c = *prefix_;
    if (c < min || c >= min + count) {

        //  The character is out of range of currently handled
        //  charcters. We have to extend the table.
        if (!count) {
            min = c;
            count = 1;
            next.node = NULL;
        }
        else if (count == 1) {
            unsigned char oldc = min;
            mtrie_t *oldp = next.node;
            count = (min < c ? c - min : min - c) + 1;
            next.table = (mtrie_t**)
                malloc (sizeof (mtrie_t*) * count);
            zmq_assert (next.table);
            for (unsigned short i = 0; i != count; ++i)
                next.table [i] = 0;
            min = std::min (min, c);
            next.table [oldc - min] = oldp;
        }
        else if (min < c) {

            //  The new character is above the current character range.
            unsigned short old_count = count;
            count = c - min + 1;
            next.table = (mtrie_t**) realloc ((void*) next.table,
                sizeof (mtrie_t*) * count);
            zmq_assert (next.table);
            for (unsigned short i = old_count; i != count; i++)
                next.table [i] = NULL;
        }
        else {

            //  The new character is below the current character range.
            unsigned short old_count = count;
            count = (min + old_count) - c;
            next.table = (mtrie_t**) realloc ((void*) next.table,
                sizeof (mtrie_t*) * count);
            zmq_assert (next.table);
            memmove (next.table + min - c, next.table,
                old_count * sizeof (mtrie_t*));
            for (unsigned short i = 0; i != min - c; i++)
                next.table [i] = NULL;
            min = c;
        }
    }

    //  If next node does not exist, create one.
    if (count == 1) {
        if (!next.node) {
            next.node = new (std::nothrow) mtrie_t;
            zmq_assert (next.node);
        }
        return next.node->add (prefix_ + 1, size_ - 1, pipe_);
    }
    else {
        if (!next.table [c - min]) {
            next.table [c - min] = new (std::nothrow) mtrie_t;
            zmq_assert (next.table [c - min]);
        }
        return next.table [c - min]->add (prefix_ + 1, size_ - 1, pipe_);
    }
}


void zmq::mtrie_t::rm (pipe_t *pipe_,
    void (*func_) (unsigned char *data_, size_t size_, void *arg_),
    void *arg_)
{
    unsigned char *buff = NULL;
    rm_helper (pipe_, &buff, 0, 0, func_, arg_);
    free (buff);
}

void zmq::mtrie_t::rm_helper (pipe_t *pipe_, unsigned char **buff_,
    size_t buffsize_, size_t maxbuffsize_,
    void (*func_) (unsigned char *data_, size_t size_, void *arg_),
    void *arg_)
{
    //  Remove the subscription from this node.
    if (pipes.erase (pipe_) && pipes.empty ())
        func_ (*buff_, buffsize_, arg_);

    //  Adjust the buffer.
    if (buffsize_ >= maxbuffsize_) {
        maxbuffsize_ = buffsize_ + 256;
        *buff_ = (unsigned char*) realloc (*buff_, maxbuffsize_);
        alloc_assert (*buff_);
    }

    //  If there are no subnodes in the trie, return.
    if (count == 0)
        return;

    //  If there's one subnode (optimisation).
    if (count == 1) {
        (*buff_) [buffsize_] = min;
        buffsize_++;
        next.node->rm_helper (pipe_, buff_, buffsize_, maxbuffsize_,
            func_, arg_);
        return;
    }

    //  If there are multiple subnodes.
    for (unsigned char c = 0; c != count; c++) {
        (*buff_) [buffsize_] = min + c;
        if (next.table [c])
            next.table [c]->rm_helper (pipe_, buff_, buffsize_ + 1,
                maxbuffsize_, func_, arg_);
    }  
}

bool zmq::mtrie_t::rm (unsigned char *prefix_, size_t size_, pipe_t *pipe_)
{
     if (!size_) {
         pipes_t::size_type erased = pipes.erase (pipe_);
         zmq_assert (erased == 1);
         return pipes.empty ();
     }

     unsigned char c = *prefix_;
     if (!count || c < min || c >= min + count)
         return false;

     mtrie_t *next_node =
         count == 1 ? next.node : next.table [c - min];

     if (!next_node)
         return false;

     return next_node->rm (prefix_ + 1, size_ - 1, pipe_);
}

void zmq::mtrie_t::match (unsigned char *data_, size_t size_, pipes_t &pipes_)
{
    //  Merge the subscriptions from this node to the resultset.
    pipes_.insert (pipes.begin (), pipes.end ());

    //  If there are no subnodes in the trie, return.
    if (count == 0)
        return;

    //  If there's one subnode (optimisation).
    if (count == 1) {
        next.node->match (data_ + 1, size_ - 1, pipes_);
        return;
    }

    //  If there are multiple subnodes.
    for (unsigned char c = 0; c != count; c++) {
        if (next.table [c])
            next.table [c]->match (data_ + 1, size_ - 1, pipes_);
    }   
}

