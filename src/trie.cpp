/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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
#include "trie.hpp"

zmq::trie_t::trie_t () :
    refcnt (0),
    min (0),
    count (0)
{
}

zmq::trie_t::~trie_t ()
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

bool zmq::trie_t::add (unsigned char *prefix_, size_t size_)
{
    //  We are at the node corresponding to the prefix. We are done.
    if (!size_) {
        ++refcnt;
        return refcnt == 1;
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
            trie_t *oldp = next.node;
            count = (min < c ? c - min : min - c) + 1;
            next.table = (trie_t**)
                malloc (sizeof (trie_t*) * count);
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
            next.table = (trie_t**) realloc ((void*) next.table,
                sizeof (trie_t*) * count);
            zmq_assert (next.table);
            for (unsigned short i = old_count; i != count; i++)
                next.table [i] = NULL;
        }
        else {

            //  The new character is below the current character range.
            unsigned short old_count = count;
            count = (min + old_count) - c;
            next.table = (trie_t**) realloc ((void*) next.table,
                sizeof (trie_t*) * count);
            zmq_assert (next.table);
            memmove (next.table + min - c, next.table,
                old_count * sizeof (trie_t*));
            for (unsigned short i = 0; i != min - c; i++)
                next.table [i] = NULL;
            min = c;
        }
    }

    //  If next node does not exist, create one.
    if (count == 1) {
        if (!next.node) {
            next.node = new (std::nothrow) trie_t;
            zmq_assert (next.node);
        }
        return next.node->add (prefix_ + 1, size_ - 1);
    }
    else {
        if (!next.table [c - min]) {
            next.table [c - min] = new (std::nothrow) trie_t;
            zmq_assert (next.table [c - min]);
        }
        return next.table [c - min]->add (prefix_ + 1, size_ - 1);
    }
}

bool zmq::trie_t::rm (unsigned char *prefix_, size_t size_)
{
     //  TODO: Shouldn't an error be reported if the key does not exist?

     if (!size_) {
         if (!refcnt)
             return false;
         refcnt--;
         return refcnt == 0;
     }

     unsigned char c = *prefix_;
     if (!count || c < min || c >= min + count)
         return false;

     trie_t *next_node =
         count == 1 ? next.node : next.table [c - min];

     if (!next_node)
         return false;

     return next_node->rm (prefix_ + 1, size_ - 1);
}

bool zmq::trie_t::check (unsigned char *data_, size_t size_)
{
    //  This function is on critical path. It deliberately doesn't use
    //  recursion to get a bit better performance.
    trie_t *current = this;
    while (true) {

        //  We've found a corresponding subscription!
        if (current->refcnt)
            return true;

        //  We've checked all the data and haven't found matching subscription.
        if (!size_)
            return false;

        //  If there's no corresponding slot for the first character
        //  of the prefix, the message does not match.
        unsigned char c = *data_;
        if (c < current->min || c >= current->min + current->count)
            return false;

        //  Move to the next character.
        if (current->count == 1)
            current = current->next.node;
        else {
            current = current->next.table [c - current->min];
            if (!current)
                return false;
        }
        data_++;
        size_--;
    }
}

void zmq::trie_t::apply (void (*func_) (unsigned char *data_, size_t size_,
    void *arg_), void *arg_)
{
    unsigned char *buff = NULL;
    apply_helper (&buff, 0, 0, func_, arg_);
    free (buff);
}

void zmq::trie_t::apply_helper (
    unsigned char **buff_, size_t buffsize_, size_t maxbuffsize_,
    void (*func_) (unsigned char *data_, size_t size_, void *arg_), void *arg_)
{
    //  If this node is a subscription, apply the function.
    if (refcnt)
        func_ (*buff_, buffsize_, arg_);

    //  Adjust the buffer.
    if (buffsize_ >= maxbuffsize_) {
        maxbuffsize_ = buffsize_ + 256;
        *buff_ = (unsigned char*) realloc (*buff_, maxbuffsize_);
        zmq_assert (*buff_);
    }

    //  If there are no subnodes in the trie, return.
    if (count == 0)
        return;

    //  If there's one subnode (optimisation).
    if (count == 1) {
        (*buff_) [buffsize_] = min;
        buffsize_++;
        next.node->apply_helper (buff_, buffsize_, maxbuffsize_, func_, arg_);
        return;
    }

    //  If there are multiple subnodes.
    for (unsigned short c = 0; c != count; c++) {
        (*buff_) [buffsize_] = min + c;
        if (next.table [c])
            next.table [c]->apply_helper (buff_, buffsize_ + 1, maxbuffsize_,
                func_, arg_);
    }   
}

