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
#include <list>

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
    class mtrie_t *it = this;

    while (size_) {
        const unsigned char c = *prefix_;

        if (c < it->min || c >= it->min + it->count) {
            //  The character is out of range of currently handled
            //  characters. We have to extend the table.
            if (!it->count) {
                it->min = c;
                it->count = 1;
                it->next.node = NULL;
            } else if (it->count == 1) {
                const unsigned char oldc = it->min;
                class mtrie_t *oldp = it->next.node;
                it->count = (it->min < c ? c - it->min : it->min - c) + 1;
                it->next.table = static_cast<class mtrie_t **> (
                  malloc (sizeof (class mtrie_t *) * it->count));
                alloc_assert (it->next.table);
                for (unsigned short i = 0; i != it->count; ++i)
                    it->next.table[i] = 0;
                it->min = std::min (it->min, c);
                it->next.table[oldc - it->min] = oldp;
            } else if (it->min < c) {
                //  The new character is above the current character range.
                const unsigned short oldcount = it->count;
                it->count = c - it->min + 1;
                it->next.table = static_cast<class mtrie_t **> (realloc (
                  it->next.table, sizeof (class mtrie_t *) * it->count));
                alloc_assert (it->next.table);
                for (unsigned short i = oldcount; i != it->count; i++)
                    it->next.table[i] = NULL;
            } else {
                //  The new character is below the current character range.
                const unsigned short oldcount = it->count;
                it->count = (it->min + oldcount) - c;
                it->next.table = static_cast<class mtrie_t **> (realloc (
                  it->next.table, sizeof (class mtrie_t *) * it->count));
                alloc_assert (it->next.table);
                memmove (it->next.table + it->min - c, it->next.table,
                         oldcount * sizeof (class mtrie_t *));
                for (unsigned short i = 0; i != it->min - c; i++)
                    it->next.table[i] = NULL;
                it->min = c;
            }
        }

        //  If next node does not exist, create one.
        if (it->count == 1) {
            if (!it->next.node) {
                it->next.node = new (std::nothrow) class mtrie_t;
                alloc_assert (it->next.node);
                ++(it->live_nodes);
            }

            ++prefix_;
            --size_;
            it = it->next.node;
        } else {
            if (!it->next.table[c - it->min]) {
                it->next.table[c - it->min] =
                  new (std::nothrow) class mtrie_t;
                alloc_assert (it->next.table[c - it->min]);
                ++(it->live_nodes);
            }

            ++prefix_;
            --size_;
            it = it->next.table[c - it->min];
        }
    }

    //  We are at the node corresponding to the prefix. We are done.
    const bool result = !it->pipes;
    if (!it->pipes) {
        it->pipes = new (std::nothrow) pipes_t;
        alloc_assert (it->pipes);
    }
    it->pipes->insert (pipe_);

    return result;
}

void zmq::mtrie_t::rm (pipe_t *pipe_,
    void (*func_) (unsigned char *data_, size_t size_, void *arg_),
    void *arg_)
{
    //  This used to be implemented as a non-tail recursive travesal of the trie,
    //  which means remote clients controlled the depth of the recursion and the
    //  stack size.
    //  To simulate the non-tail recursion, with post-recursion changes depending on
    //  the result of the recursive call, a stack is used to re-visit the same node
    //  and operate on it again after children have been visisted.
    //  A boolean is used to record whether the node had already been visited and to
    //  determine if the pre- or post- children visit actions have to be taken.
    //  In the case of a node with (N > 1) children, the node has to be re-visited
    //  N times, in the correct order after each child visit.
    std::list<struct iter> stack;
    unsigned char *buff = NULL;
    size_t maxbuffsize = 0;
    struct iter it = {this, NULL, NULL, 0, 0, 0, false};
    stack.push_back (it);

    while (!stack.empty ()) {
        it = stack.back ();
        stack.pop_back ();

        if (!it.processed_for_removal) {
            //  Remove the subscription from this node.
            if (it.node->pipes && it.node->pipes->erase (pipe_)) {
                if (it.node->pipes->empty ()) {
                    func_ (buff, it.size, arg_);
                }

                if (it.node->pipes->empty ()) {
                    delete it.node->pipes;
                    it.node->pipes = NULL;
                }
            }

            //  Adjust the buffer.
            if (it.size >= maxbuffsize) {
                maxbuffsize = it.size + 256;
                buff =
                  static_cast<unsigned char *> (realloc (buff, maxbuffsize));
                alloc_assert (buff);
            }

            switch (it.node->count) {
                case 0:
                    //  If there are no subnodes in the trie, we are done with this node
                    //  pre-processing.
                    break;
                case 1: {
                    //  If there's one subnode (optimisation).

                    buff[it.size] = it.node->min;
                    //  Mark this node as pre-processed and push it, so that the next
                    //  visit after the operation on the child can do the removals.
                    it.processed_for_removal = true;
                    stack.push_back (it);
                    struct iter next = {
                      it.node->next.node, NULL, NULL, ++it.size, 0, 0, false};
                    stack.push_back (next);
                    break;
                }
                default: {
                    //  If there are multiple subnodes.
                    //  When first visiting this node, initialize the new_min/max parameters
                    //  which will then be used after each child has been processed, on the
                    //  post-children iterations.
                    if (it.current_child == 0) {
                        //  New min non-null character in the node table after the removal
                        it.new_min = it.node->min + it.node->count - 1;
                        //  New max non-null character in the node table after the removal
                        it.new_max = it.node->min;
                    }

                    //  Mark this node as pre-processed and push it, so that the next
                    //  visit after the operation on the child can do the removals.
                    buff[it.size] = it.node->min + it.current_child;
                    it.processed_for_removal = true;
                    stack.push_back (it);
                    if (it.node->next.table[it.current_child]) {
                        struct iter next = {
                          it.node->next.table[it.current_child],
                          NULL,
                          NULL,
                          it.size + 1,
                          0,
                          0,
                          false};
                        stack.push_back (next);
                    }
                }
            }
        } else {
            //  Reset back for the next time, in case this node doesn't get deleted.
            //  This is done unconditionally, unlike when setting this variable to true.
            it.processed_for_removal = false;

            switch (it.node->count) {
                case 0:
                    //  If there are no subnodes in the trie, we are done with this node
                    //  post-processing.
                    break;
                case 1:
                    //  If there's one subnode (optimisation).

                    //  Prune the node if it was made redundant by the removal
                    if (it.node->next.node->is_redundant ()) {
                        delete it.node->next.node;
                        it.node->next.node = NULL;
                        it.node->count = 0;
                        --it.node->live_nodes;
                        zmq_assert (it.node->live_nodes == 0);
                    }
                    break;
                default:
                    //  If there are multiple subnodes.
                    {
                        if (it.node->next.table[it.current_child]) {
                            //  Prune redundant nodes from the mtrie
                            if (it.node->next.table[it.current_child]
                                  ->is_redundant ()) {
                                delete it.node->next.table[it.current_child];
                                it.node->next.table[it.current_child] = NULL;

                                zmq_assert (it.node->live_nodes > 0);
                                --it.node->live_nodes;
                            } else {
                                //  The node is not redundant, so it's a candidate for being
                                //  the new min/max node.
                                //
                                //  We loop through the node array from left to right, so the
                                //  first non-null, non-redundant node encountered is the new
                                //  minimum index. Conversely, the last non-redundant, non-null
                                //  node encountered is the new maximum index.
                                if (it.current_child + it.node->min
                                    < it.new_min)
                                    it.new_min =
                                      it.current_child + it.node->min;
                                if (it.current_child + it.node->min
                                    > it.new_max)
                                    it.new_max =
                                      it.current_child + it.node->min;
                            }
                        }

                        //  If there are more children to visit, push again the current
                        //  node, so that pre-processing can happen on the next child.
                        //  If we are done, reset the child index so that the ::rm is
                        //  fully idempotent.
                        ++it.current_child;
                        if (it.current_child >= it.node->count)
                            it.current_child = 0;
                        else {
                            stack.push_back (it);
                            continue;
                        }

                        //  All children have been visited and removed if needed, and
                        //  all pre- and post-visit operations have been carried.
                        //  Resize/free the node table if needed.
                        zmq_assert (it.node->count > 1);

                        //  Free the node table if it's no longer used.
                        switch (it.node->live_nodes) {
                            case 0:
                                free (it.node->next.table);
                                it.node->next.table = NULL;
                                it.node->count = 0;
                                break;
                            case 1:
                                //  Compact the node table if possible

                                //  If there's only one live node in the table we can
                                //  switch to using the more compact single-node
                                //  representation
                                zmq_assert (it.new_min == it.new_max);
                                zmq_assert (it.new_min >= it.node->min);
                                zmq_assert (it.new_min
                                            < it.node->min + it.node->count);
                                {
                                    class mtrie_t *node =
                                      it.node->next
                                        .table[it.new_min - it.node->min];
                                    zmq_assert (node);
                                    free (it.node->next.table);
                                    it.node->next.node = node;
                                }
                                it.node->count = 1;
                                it.node->min = it.new_min;
                                break;
                            default:
                                if (it.new_min > it.node->min
                                    || it.new_max < it.node->min
                                                      + it.node->count - 1) {
                                    zmq_assert (it.new_max - it.new_min + 1
                                                > 1);

                                    class mtrie_t **old_table =
                                      it.node->next.table;
                                    zmq_assert (it.new_min > it.node->min
                                                || it.new_max
                                                     < it.node->min
                                                         + it.node->count - 1);
                                    zmq_assert (it.new_min >= it.node->min);
                                    zmq_assert (it.new_max
                                                <= it.node->min
                                                     + it.node->count - 1);
                                    zmq_assert (it.new_max - it.new_min + 1
                                                < it.node->count);

                                    it.node->count =
                                      it.new_max - it.new_min + 1;
                                    it.node->next.table =
                                      static_cast<class mtrie_t **> (
                                        malloc (sizeof (class mtrie_t *)
                                                * it.node->count));
                                    alloc_assert (it.node->next.table);

                                    memmove (it.node->next.table,
                                             old_table
                                               + (it.new_min - it.node->min),
                                             sizeof (class mtrie_t *)
                                               * it.node->count);
                                    free (old_table);

                                    it.node->min = it.new_min;
                                }
                        }
                    }
            }
        }
    }

    free (buff);
}

bool zmq::mtrie_t::rm (unsigned char *prefix_, size_t size_, zmq::pipe_t *pipe_)
{
    //  This used to be implemented as a non-tail recursive travesal of the trie,
    //  which means remote clients controlled the depth of the recursion and the
    //  stack size.
    //  To simulate the non-tail recursion, with post-recursion changes depending on
    //  the result of the recursive call, a stack is used to re-visit the same node
    //  and operate on it again after children have been visisted.
    //  A boolean is used to record whether the node had already been visited and to
    //  determine if the pre- or post- children visit actions have to be taken.
    bool ret = false;
    std::list<struct iter> stack;
    struct iter it = {this, NULL, prefix_, size_, 0, 0, 0, false};
    stack.push_back (it);

    while (!stack.empty ()) {
        it = stack.back ();
        stack.pop_back ();

        if (!it.processed_for_removal) {
            if (!it.size) {
                if (!it.node->pipes) {
                    ret = false;
                    continue;
                }

                typename pipes_t::size_type erased =
                  it.node->pipes->erase (pipe_);
                if (it.node->pipes->empty ()) {
                    zmq_assert (erased == 1);
                    delete it.node->pipes;
                    it.node->pipes = NULL;
                    ret = true;
                    continue;
                }

                ret = (erased == 1);
                continue;
            }

            it.current_child = *it.prefix;
            if (!it.node->count || it.current_child < it.node->min
                || it.current_child >= it.node->min + it.node->count) {
                ret = false;
                continue;
            }

            it.next_node =
              it.node->count == 1
                ? it.node->next.node
                : it.node->next.table[it.current_child - it.node->min];
            if (!it.next_node) {
                ret = false;
                continue;
            }

            it.processed_for_removal = true;
            stack.push_back (it);
            struct iter next = {
              it.next_node, NULL, it.prefix + 1, it.size - 1, 0, 0, 0, false};
            stack.push_back (next);
        } else {
            it.processed_for_removal = false;

            if (it.next_node->is_redundant ()) {
                delete it.next_node;
                it.next_node = NULL;
                zmq_assert (it.node->count > 0);

                if (it.node->count == 1) {
                    it.node->next.node = NULL;
                    it.node->count = 0;
                    --it.node->live_nodes;
                    zmq_assert (it.node->live_nodes == 0);
                } else {
                    it.node->next.table[it.current_child - it.node->min] = 0;
                    zmq_assert (it.node->live_nodes > 1);
                    --it.node->live_nodes;

                    //  Compact the table if possible
                    if (it.node->live_nodes == 1) {
                        //  If there's only one live node in the table we can
                        //  switch to using the more compact single-node
                        //  representation
                        unsigned short i;
                        for (i = 0; i < it.node->count; ++i)
                            if (it.node->next.table[i])
                                break;

                        zmq_assert (i < it.node->count);
                        it.node->min += i;
                        it.node->count = 1;
                        class mtrie_t *oldp = it.node->next.table[i];
                        free (it.node->next.table);
                        it.node->next.table = NULL;
                        it.node->next.node = oldp;
                    } else if (it.current_child == it.node->min) {
                        //  We can compact the table "from the left"
                        unsigned short i;
                        for (i = 1; i < it.node->count; ++i)
                            if (it.node->next.table[i])
                                break;

                        zmq_assert (i < it.node->count);
                        it.node->min += i;
                        it.node->count -= i;
                        class mtrie_t **old_table = it.node->next.table;
                        it.node->next.table =
                          static_cast<class mtrie_t **> (malloc (
                            sizeof (class mtrie_t *) * it.node->count));
                        alloc_assert (it.node->next.table);
                        memmove (it.node->next.table, old_table + i,
                                 sizeof (class mtrie_t *) * it.node->count);
                        free (old_table);
                    } else if (it.current_child
                               == it.node->min + it.node->count - 1) {
                        //  We can compact the table "from the right"
                        unsigned short i;
                        for (i = 1; i < it.node->count; ++i)
                            if (it.node->next.table[it.node->count - 1 - i])
                                break;

                        zmq_assert (i < it.node->count);
                        it.node->count -= i;
                        class mtrie_t **old_table = it.node->next.table;
                        it.node->next.table =
                          static_cast<class mtrie_t **> (malloc (
                            sizeof (class mtrie_t *) * it.node->count));
                        alloc_assert (it.node->next.table);
                        memmove (it.node->next.table, old_table,
                                 sizeof (class mtrie_t *) * it.node->count);
                        free (old_table);
                    }
                }
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
