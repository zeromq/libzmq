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

#ifndef __ZMQ_GENERIC_MTRIE_IMPL_HPP_INCLUDED__
#define __ZMQ_GENERIC_MTRIE_IMPL_HPP_INCLUDED__


#include <stdlib.h>

#include <new>
#include <algorithm>
#include <list>

#include "err.hpp"
#include "macros.hpp"
#include "generic_mtrie.hpp"

namespace zmq
{
template <typename T>
generic_mtrie_t<T>::generic_mtrie_t () :
    _pipes (0),
    _min (0),
    _count (0),
    _live_nodes (0)
{
}

template <typename T> generic_mtrie_t<T>::~generic_mtrie_t ()
{
    LIBZMQ_DELETE (_pipes);

    if (_count == 1) {
        zmq_assert (_next.node);
        LIBZMQ_DELETE (_next.node);
    } else if (_count > 1) {
        for (unsigned short i = 0; i != _count; ++i) {
            LIBZMQ_DELETE (_next.table[i]);
        }
        free (_next.table);
    }
}

template <typename T>
bool generic_mtrie_t<T>::add (prefix_t prefix_, size_t size_, value_t *pipe_)
{
    generic_mtrie_t<value_t> *it = this;

    while (size_) {
        const unsigned char c = *prefix_;

        if (c < it->_min || c >= it->_min + it->_count) {
            //  The character is out of range of currently handled
            //  characters. We have to extend the table.
            if (!it->_count) {
                it->_min = c;
                it->_count = 1;
                it->_next.node = NULL;
            } else if (it->_count == 1) {
                const unsigned char oldc = it->_min;
                generic_mtrie_t *oldp = it->_next.node;
                it->_count = (it->_min < c ? c - it->_min : it->_min - c) + 1;
                it->_next.table = static_cast<generic_mtrie_t **> (
                  malloc (sizeof (generic_mtrie_t *) * it->_count));
                alloc_assert (it->_next.table);
                for (unsigned short i = 0; i != it->_count; ++i)
                    it->_next.table[i] = 0;
                it->_min = std::min (it->_min, c);
                it->_next.table[oldc - it->_min] = oldp;
            } else if (it->_min < c) {
                //  The new character is above the current character range.
                const unsigned short old_count = it->_count;
                it->_count = c - it->_min + 1;
                it->_next.table = static_cast<generic_mtrie_t **> (realloc (
                  it->_next.table, sizeof (generic_mtrie_t *) * it->_count));
                alloc_assert (it->_next.table);
                for (unsigned short i = old_count; i != it->_count; i++)
                    it->_next.table[i] = NULL;
            } else {
                //  The new character is below the current character range.
                const unsigned short old_count = it->_count;
                it->_count = (it->_min + old_count) - c;
                it->_next.table = static_cast<generic_mtrie_t **> (realloc (
                  it->_next.table, sizeof (generic_mtrie_t *) * it->_count));
                alloc_assert (it->_next.table);
                memmove (it->_next.table + it->_min - c, it->_next.table,
                         old_count * sizeof (generic_mtrie_t *));
                for (unsigned short i = 0; i != it->_min - c; i++)
                    it->_next.table[i] = NULL;
                it->_min = c;
            }
        }

        //  If next node does not exist, create one.
        if (it->_count == 1) {
            if (!it->_next.node) {
                it->_next.node = new (std::nothrow) generic_mtrie_t;
                alloc_assert (it->_next.node);
                ++(it->_live_nodes);
            }

            ++prefix_;
            --size_;
            it = it->_next.node;
        } else {
            if (!it->_next.table[c - it->_min]) {
                it->_next.table[c - it->_min] =
                  new (std::nothrow) generic_mtrie_t;
                alloc_assert (it->_next.table[c - it->_min]);
                ++(it->_live_nodes);
            }

            ++prefix_;
            --size_;
            it = it->_next.table[c - it->_min];
        }
    }

    //  We are at the node corresponding to the prefix. We are done.
    const bool result = !it->_pipes;
    if (!it->_pipes) {
        it->_pipes = new (std::nothrow) pipes_t;
        alloc_assert (it->_pipes);
    }
    it->_pipes->insert (pipe_);

    return result;
}

template <typename T>
template <typename Arg>
void generic_mtrie_t<T>::rm (value_t *pipe_,
                             void (*func_) (prefix_t data_,
                                            size_t size_,
                                            Arg arg_),
                             Arg arg_,
                             bool call_on_uniq_)
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
            if (it.node->_pipes && it.node->_pipes->erase (pipe_)) {
                if (!call_on_uniq_ || it.node->_pipes->empty ()) {
                    func_ (buff, it.size, arg_);
                }

                if (it.node->_pipes->empty ()) {
                    LIBZMQ_DELETE (it.node->_pipes);
                }
            }

            //  Adjust the buffer.
            if (it.size >= maxbuffsize) {
                maxbuffsize = it.size + 256;
                buff =
                  static_cast<unsigned char *> (realloc (buff, maxbuffsize));
                alloc_assert (buff);
            }

            switch (it.node->_count) {
                case 0:
                    //  If there are no subnodes in the trie, we are done with this node
                    //  pre-processing.
                    break;
                case 1: {
                    //  If there's one subnode (optimisation).

                    buff[it.size] = it.node->_min;
                    //  Mark this node as pre-processed and push it, so that the next
                    //  visit after the operation on the child can do the removals.
                    it.processed_for_removal = true;
                    stack.push_back (it);
                    struct iter next = {
                      it.node->_next.node, NULL, NULL, ++it.size, 0, 0, false};
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
                        it.new_min = it.node->_min + it.node->_count - 1;
                        //  New max non-null character in the node table after the removal
                        it.new_max = it.node->_min;
                    }

                    //  Mark this node as pre-processed and push it, so that the next
                    //  visit after the operation on the child can do the removals.
                    buff[it.size] = it.node->_min + it.current_child;
                    it.processed_for_removal = true;
                    stack.push_back (it);
                    if (it.node->_next.table[it.current_child]) {
                        struct iter next = {
                          it.node->_next.table[it.current_child],
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

            switch (it.node->_count) {
                case 0:
                    //  If there are no subnodes in the trie, we are done with this node
                    //  post-processing.
                    break;
                case 1:
                    //  If there's one subnode (optimisation).

                    //  Prune the node if it was made redundant by the removal
                    if (it.node->_next.node->is_redundant ()) {
                        LIBZMQ_DELETE (it.node->_next.node);
                        it.node->_count = 0;
                        --it.node->_live_nodes;
                        zmq_assert (it.node->_live_nodes == 0);
                    }
                    break;
                default:
                    //  If there are multiple subnodes.
                    {
                        if (it.node->_next.table[it.current_child]) {
                            //  Prune redundant nodes from the mtrie
                            if (it.node->_next.table[it.current_child]
                                  ->is_redundant ()) {
                                LIBZMQ_DELETE (
                                  it.node->_next.table[it.current_child]);

                                zmq_assert (it.node->_live_nodes > 0);
                                --it.node->_live_nodes;
                            } else {
                                //  The node is not redundant, so it's a candidate for being
                                //  the new min/max node.
                                //
                                //  We loop through the node array from left to right, so the
                                //  first non-null, non-redundant node encountered is the new
                                //  minimum index. Conversely, the last non-redundant, non-null
                                //  node encountered is the new maximum index.
                                if (it.current_child + it.node->_min
                                    < it.new_min)
                                    it.new_min =
                                      it.current_child + it.node->_min;
                                if (it.current_child + it.node->_min
                                    > it.new_max)
                                    it.new_max =
                                      it.current_child + it.node->_min;
                            }
                        }

                        //  If there are more children to visit, push again the current
                        //  node, so that pre-processing can happen on the next child.
                        //  If we are done, reset the child index so that the ::rm is
                        //  fully idempotent.
                        ++it.current_child;
                        if (it.current_child >= it.node->_count)
                            it.current_child = 0;
                        else {
                            stack.push_back (it);
                            continue;
                        }

                        //  All children have been visited and removed if needed, and
                        //  all pre- and post-visit operations have been carried.
                        //  Resize/free the node table if needed.
                        zmq_assert (it.node->_count > 1);

                        //  Free the node table if it's no longer used.
                        switch (it.node->_live_nodes) {
                            case 0:
                                free (it.node->_next.table);
                                it.node->_next.table = NULL;
                                it.node->_count = 0;
                                break;
                            case 1:
                                //  Compact the node table if possible

                                //  If there's only one live node in the table we can
                                //  switch to using the more compact single-node
                                //  representation
                                zmq_assert (it.new_min == it.new_max);
                                zmq_assert (it.new_min >= it.node->_min);
                                zmq_assert (it.new_min
                                            < it.node->_min + it.node->_count);
                                {
                                    generic_mtrie_t *node =
                                      it.node->_next
                                        .table[it.new_min - it.node->_min];
                                    zmq_assert (node);
                                    free (it.node->_next.table);
                                    it.node->_next.node = node;
                                }
                                it.node->_count = 1;
                                it.node->_min = it.new_min;
                                break;
                            default:
                                if (it.new_min > it.node->_min
                                    || it.new_max < it.node->_min
                                                      + it.node->_count - 1) {
                                    zmq_assert (it.new_max - it.new_min + 1
                                                > 1);

                                    generic_mtrie_t **old_table =
                                      it.node->_next.table;
                                    zmq_assert (it.new_min > it.node->_min
                                                || it.new_max
                                                     < it.node->_min
                                                         + it.node->_count - 1);
                                    zmq_assert (it.new_min >= it.node->_min);
                                    zmq_assert (it.new_max
                                                <= it.node->_min
                                                     + it.node->_count - 1);
                                    zmq_assert (it.new_max - it.new_min + 1
                                                < it.node->_count);

                                    it.node->_count =
                                      it.new_max - it.new_min + 1;
                                    it.node->_next.table =
                                      static_cast<generic_mtrie_t **> (
                                        malloc (sizeof (generic_mtrie_t *)
                                                * it.node->_count));
                                    alloc_assert (it.node->_next.table);

                                    memmove (it.node->_next.table,
                                             old_table
                                               + (it.new_min - it.node->_min),
                                             sizeof (generic_mtrie_t *)
                                               * it.node->_count);
                                    free (old_table);

                                    it.node->_min = it.new_min;
                                }
                        }
                    }
            }
        }
    }

    free (buff);
}

template <typename T>
typename generic_mtrie_t<T>::rm_result
generic_mtrie_t<T>::rm (prefix_t prefix_, size_t size_, value_t *pipe_)
{
    //  This used to be implemented as a non-tail recursive travesal of the trie,
    //  which means remote clients controlled the depth of the recursion and the
    //  stack size.
    //  To simulate the non-tail recursion, with post-recursion changes depending on
    //  the result of the recursive call, a stack is used to re-visit the same node
    //  and operate on it again after children have been visisted.
    //  A boolean is used to record whether the node had already been visited and to
    //  determine if the pre- or post- children visit actions have to be taken.
    rm_result ret = not_found;
    std::list<struct iter> stack;
    struct iter it = {this, NULL, prefix_, size_, 0, 0, 0, false};
    stack.push_back (it);

    while (!stack.empty ()) {
        it = stack.back ();
        stack.pop_back ();

        if (!it.processed_for_removal) {
            if (!it.size) {
                if (!it.node->_pipes) {
                    ret = not_found;
                    continue;
                }

                typename pipes_t::size_type erased =
                  it.node->_pipes->erase (pipe_);
                if (it.node->_pipes->empty ()) {
                    zmq_assert (erased == 1);
                    LIBZMQ_DELETE (it.node->_pipes);
                    ret = last_value_removed;
                    continue;
                }

                ret = (erased == 1) ? values_remain : not_found;
                continue;
            }

            it.current_child = *it.prefix;
            if (!it.node->_count || it.current_child < it.node->_min
                || it.current_child >= it.node->_min + it.node->_count) {
                ret = not_found;
                continue;
            }

            it.next_node =
              it.node->_count == 1
                ? it.node->_next.node
                : it.node->_next.table[it.current_child - it.node->_min];
            if (!it.next_node) {
                ret = not_found;
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
                LIBZMQ_DELETE (it.next_node);
                zmq_assert (it.node->_count > 0);

                if (it.node->_count == 1) {
                    it.node->_next.node = NULL;
                    it.node->_count = 0;
                    --it.node->_live_nodes;
                    zmq_assert (it.node->_live_nodes == 0);
                } else {
                    it.node->_next.table[it.current_child - it.node->_min] = 0;
                    zmq_assert (it.node->_live_nodes > 1);
                    --it.node->_live_nodes;

                    //  Compact the table if possible
                    if (it.node->_live_nodes == 1) {
                        //  If there's only one live node in the table we can
                        //  switch to using the more compact single-node
                        //  representation
                        unsigned short i;
                        for (i = 0; i < it.node->_count; ++i)
                            if (it.node->_next.table[i])
                                break;

                        zmq_assert (i < it.node->_count);
                        it.node->_min += i;
                        it.node->_count = 1;
                        generic_mtrie_t *oldp = it.node->_next.table[i];
                        free (it.node->_next.table);
                        it.node->_next.table = NULL;
                        it.node->_next.node = oldp;
                    } else if (it.current_child == it.node->_min) {
                        //  We can compact the table "from the left"
                        unsigned short i;
                        for (i = 1; i < it.node->_count; ++i)
                            if (it.node->_next.table[i])
                                break;

                        zmq_assert (i < it.node->_count);
                        it.node->_min += i;
                        it.node->_count -= i;
                        generic_mtrie_t **old_table = it.node->_next.table;
                        it.node->_next.table =
                          static_cast<generic_mtrie_t **> (malloc (
                            sizeof (generic_mtrie_t *) * it.node->_count));
                        alloc_assert (it.node->_next.table);
                        memmove (it.node->_next.table, old_table + i,
                                 sizeof (generic_mtrie_t *) * it.node->_count);
                        free (old_table);
                    } else if (it.current_child
                               == it.node->_min + it.node->_count - 1) {
                        //  We can compact the table "from the right"
                        unsigned short i;
                        for (i = 1; i < it.node->_count; ++i)
                            if (it.node->_next.table[it.node->_count - 1 - i])
                                break;

                        zmq_assert (i < it.node->_count);
                        it.node->_count -= i;
                        generic_mtrie_t **old_table = it.node->_next.table;
                        it.node->_next.table =
                          static_cast<generic_mtrie_t **> (malloc (
                            sizeof (generic_mtrie_t *) * it.node->_count));
                        alloc_assert (it.node->_next.table);
                        memmove (it.node->_next.table, old_table,
                                 sizeof (generic_mtrie_t *) * it.node->_count);
                        free (old_table);
                    }
                }
            }
        }
    }

    return ret;
}

template <typename T>
template <typename Arg>
void generic_mtrie_t<T>::match (prefix_t data_,
                                size_t size_,
                                void (*func_) (value_t *pipe_, Arg arg_),
                                Arg arg_)
{
    for (generic_mtrie_t *current = this; current; data_++, size_--) {
        //  Signal the pipes attached to this node.
        if (current->_pipes) {
            for (typename pipes_t::iterator it = current->_pipes->begin (),
                                            end = current->_pipes->end ();
                 it != end; ++it) {
                func_ (*it, arg_);
            }
        }

        //  If we are at the end of the message, there's nothing more to match.
        if (!size_)
            break;

        //  If there are no subnodes in the trie, return.
        if (current->_count == 0)
            break;

        if (current->_count == 1) {
            //  If there's one subnode (optimisation).
            if (data_[0] != current->_min) {
                break;
            }
            current = current->_next.node;
        } else {
            //  If there are multiple subnodes.
            if (data_[0] < current->_min
                || data_[0] >= current->_min + current->_count) {
                break;
            }
            current = current->_next.table[data_[0] - current->_min];
        }
    }
}

template <typename T> bool generic_mtrie_t<T>::is_redundant () const
{
    return !_pipes && _live_nodes == 0;
}
}


#endif
