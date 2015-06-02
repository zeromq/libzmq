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
    pipes (0),
    min (0),
    count (0),
    live_nodes (0)
{
}

zmq::mtrie_t::~mtrie_t ()
{
    if (pipes) {
        delete pipes;
        pipes = 0;
    }

    if (count == 1) {
        zmq_assert (next.node);
        delete next.node;
        next.node = 0;
    }
    else
    if (count > 1) {
        for (unsigned short i = 0; i != count; ++i)
            delete next.table [i];
        free (next.table);
    }
}

bool zmq::mtrie_t::add (unsigned char *prefix_, size_t size_, pipe_t *pipe_)
{
    return add_helper (prefix_, size_, pipe_);
}

bool zmq::mtrie_t::add_helper (unsigned char *prefix_, size_t size_,
    pipe_t *pipe_)
{
    //  We are at the node corresponding to the prefix. We are done.
    if (!size_) {
        bool result = !pipes;
        if (!pipes) {
            pipes = new (std::nothrow) pipes_t;
            alloc_assert (pipes);
        }
        pipes->insert (pipe_);
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
        else
        if (count == 1) {
            unsigned char oldc = min;
            mtrie_t *oldp = next.node;
            count = (min < c ? c - min : min - c) + 1;
            next.table = (mtrie_t**)
                malloc (sizeof (mtrie_t*) * count);
            alloc_assert (next.table);
            for (unsigned short i = 0; i != count; ++i)
                next.table [i] = 0;
            min = std::min (min, c);
            next.table [oldc - min] = oldp;
        }
        else
        if (min < c) {
            //  The new character is above the current character range.
            unsigned short old_count = count;
            count = c - min + 1;
            next.table = (mtrie_t**) realloc (next.table,
                sizeof (mtrie_t*) * count);
            alloc_assert (next.table);
            for (unsigned short i = old_count; i != count; i++)
                next.table [i] = NULL;
        }
        else {
            //  The new character is below the current character range.
            unsigned short old_count = count;
            count = (min + old_count) - c;
            next.table = (mtrie_t**) realloc (next.table,
                sizeof (mtrie_t*) * count);
            alloc_assert (next.table);
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
            alloc_assert (next.node);
            ++live_nodes;
        }
        return next.node->add_helper (prefix_ + 1, size_ - 1, pipe_);
    }
    else {
        if (!next.table [c - min]) {
            next.table [c - min] = new (std::nothrow) mtrie_t;
            alloc_assert (next.table [c - min]);
            ++live_nodes;
        }
        return next.table [c - min]->add_helper (prefix_ + 1, size_ - 1, pipe_);
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
    if (pipes && pipes->erase (pipe_) && pipes->empty ()) {
        func_ (*buff_, buffsize_, arg_);
        delete pipes;
        pipes = 0;
    }

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

        //  Prune the node if it was made redundant by the removal
        if (next.node->is_redundant ()) {
            delete next.node;
            next.node = 0;
            count = 0;
            --live_nodes;
            zmq_assert (live_nodes == 0);
        }
        return;
    }

    //  If there are multiple subnodes.
    //
    //  New min non-null character in the node table after the removal
    unsigned char new_min = min + count - 1;
    //  New max non-null character in the node table after the removal
    unsigned char new_max = min;
    for (unsigned short c = 0; c != count; c++) {
        (*buff_) [buffsize_] = min + c;
        if (next.table [c]) {
            next.table [c]->rm_helper (pipe_, buff_, buffsize_ + 1,
                maxbuffsize_, func_, arg_);

            //  Prune redundant nodes from the mtrie
            if (next.table [c]->is_redundant ()) {
                delete next.table [c];
                next.table [c] = 0;

                zmq_assert (live_nodes > 0);
                --live_nodes;
            }
            else {
                //  The node is not redundant, so it's a candidate for being
                //  the new min/max node.
                //
                //  We loop through the node array from left to right, so the
                //  first non-null, non-redundant node encountered is the new
                //  minimum index. Conversely, the last non-redundant, non-null
                //  node encountered is the new maximum index.
                if (c + min < new_min)
                    new_min = c + min;
                if (c + min > new_max)
                    new_max = c + min;
            }
        }
    }

    zmq_assert (count > 1);

    //  Free the node table if it's no longer used.
    if (live_nodes == 0) {
        free (next.table);
        next.table = NULL;
        count = 0;
    }
    //  Compact the node table if possible
    else
    if (live_nodes == 1) {
        //  If there's only one live node in the table we can
        //  switch to using the more compact single-node
        //  representation
        zmq_assert (new_min == new_max);
        zmq_assert (new_min >= min && new_min < min + count);
        mtrie_t *node = next.table [new_min - min];
        zmq_assert (node);
        free (next.table);
        next.node = node;
        count = 1;
        min = new_min;
    }
    else
    if (new_min > min || new_max < min + count - 1) {
        zmq_assert (new_max - new_min + 1 > 1);

        mtrie_t **old_table = next.table;
        zmq_assert (new_min > min || new_max < min + count - 1);
        zmq_assert (new_min >= min);
        zmq_assert (new_max <= min + count - 1);
        zmq_assert (new_max - new_min + 1 < count);

        count = new_max - new_min + 1;
        next.table = (mtrie_t**) malloc (sizeof (mtrie_t*) * count);
        alloc_assert (next.table);

        memmove (next.table, old_table + (new_min - min),
                 sizeof (mtrie_t*) * count);
        free (old_table);

        min = new_min;
    }
}

bool zmq::mtrie_t::rm (unsigned char *prefix_, size_t size_, pipe_t *pipe_)
{
    return rm_helper (prefix_, size_, pipe_);
}

bool zmq::mtrie_t::rm_helper (unsigned char *prefix_, size_t size_,
    pipe_t *pipe_)
{
    if (!size_) {
        if (pipes) {
            pipes_t::size_type erased = pipes->erase (pipe_);
            zmq_assert (erased == 1);
            if (pipes->empty ()) {
                delete pipes;
                pipes = 0;
            }
        }
        return !pipes;
    }

    unsigned char c = *prefix_;
    if (!count || c < min || c >= min + count)
        return false;

    mtrie_t *next_node =
        count == 1 ? next.node : next.table [c - min];

    if (!next_node)
        return false;

    bool ret = next_node->rm_helper (prefix_ + 1, size_ - 1, pipe_);

    if (next_node->is_redundant ()) {
        delete next_node;
        zmq_assert (count > 0);

        if (count == 1) {
            next.node = 0;
            count = 0;
            --live_nodes;
            zmq_assert (live_nodes == 0);
        }
        else {
            next.table [c - min] = 0;
            zmq_assert (live_nodes > 1);
            --live_nodes;

            //  Compact the table if possible
            if (live_nodes == 1) {
                //  If there's only one live node in the table we can
                //  switch to using the more compact single-node
                //  representation
                unsigned short i;
                for (i = 0; i < count; ++i)
                    if (next.table [i])
                        break;

                zmq_assert (i < count);
                min += i;
                count = 1;
                mtrie_t *oldp = next.table [i];
                free (next.table);
                next.node = oldp;
            }
            else
            if (c == min) {
                //  We can compact the table "from the left"
                unsigned short i;
                for (i = 1; i < count; ++i)
                    if (next.table [i])
                        break;

                zmq_assert (i < count);
                min += i;
                count -= i;
                mtrie_t **old_table = next.table;
                next.table = (mtrie_t**) malloc (sizeof (mtrie_t*) * count);
                alloc_assert (next.table);
                memmove (next.table, old_table + i, sizeof (mtrie_t*) * count);
                free (old_table);
            }
            else
            if (c == min + count - 1) {
                //  We can compact the table "from the right"
                unsigned short i;
                for (i = 1; i < count; ++i)
                    if (next.table [count - 1 - i])
                        break;

                zmq_assert (i < count);
                count -= i;
                mtrie_t **old_table = next.table;
                next.table = (mtrie_t**) malloc (sizeof (mtrie_t*) * count);
                alloc_assert (next.table);
                memmove (next.table, old_table, sizeof (mtrie_t*) * count);
                free (old_table);
            }
        }
    }

    return ret;
}

void zmq::mtrie_t::match (unsigned char *data_, size_t size_,
    void (*func_) (pipe_t *pipe_, void *arg_), void *arg_)
{
    mtrie_t *current = this;
    while (true) {

        //  Signal the pipes attached to this node.
        if (current->pipes) {
            for (pipes_t::iterator it = current->pipes->begin ();
                  it != current->pipes->end (); ++it)
                func_ (*it, arg_);
        }

        //  If we are at the end of the message, there's nothing more to match.
        if (!size_)
            break;

        //  If there are no subnodes in the trie, return.
        if (current->count == 0)
            break;

        //  If there's one subnode (optimisation).
		if (current->count == 1) {
            if (data_ [0] != current->min)
                break;
            current = current->next.node;
            data_++;
            size_--;
		    continue;
		}

		//  If there are multiple subnodes.
        if (data_ [0] < current->min || data_ [0] >=
              current->min + current->count)
            break;
        if (!current->next.table [data_ [0] - current->min])
            break;
        current = current->next.table [data_ [0] - current->min];
        data_++;
        size_--;
    }
}

bool zmq::mtrie_t::is_redundant () const
{
    return !pipes && live_nodes == 0;
}
