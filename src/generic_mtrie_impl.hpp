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

#include "err.hpp"
#include "macros.hpp"
#include "generic_mtrie.hpp"

template <typename T>
zmq::generic_mtrie_t<T>::generic_mtrie_t () :
    _pipes (0),
    _min (0),
    _count (0),
    _live_nodes (0)
{
}

template <typename T> zmq::generic_mtrie_t<T>::~generic_mtrie_t ()
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
bool zmq::generic_mtrie_t<T>::add (prefix_t prefix_,
                                   size_t size_,
                                   value_t *pipe_)
{
    return add_helper (prefix_, size_, pipe_);
}

template <typename T>
bool zmq::generic_mtrie_t<T>::add_helper (prefix_t prefix_,
                                          size_t size_,
                                          value_t *pipe_)
{
    //  We are at the node corresponding to the prefix. We are done.
    if (!size_) {
        const bool result = !_pipes;
        if (!_pipes) {
            _pipes = new (std::nothrow) pipes_t;
            alloc_assert (_pipes);
        }
        _pipes->insert (pipe_);
        return result;
    }

    const unsigned char c = *prefix_;
    if (c < _min || c >= _min + _count) {
        //  The character is out of range of currently handled
        //  characters. We have to extend the table.
        if (!_count) {
            _min = c;
            _count = 1;
            _next.node = NULL;
        } else if (_count == 1) {
            const unsigned char oldc = _min;
            generic_mtrie_t *oldp = _next.node;
            _count = (_min < c ? c - _min : _min - c) + 1;
            _next.table = static_cast<generic_mtrie_t **> (
              malloc (sizeof (generic_mtrie_t *) * _count));
            alloc_assert (_next.table);
            for (unsigned short i = 0; i != _count; ++i)
                _next.table[i] = 0;
            _min = std::min (_min, c);
            _next.table[oldc - _min] = oldp;
        } else if (_min < c) {
            //  The new character is above the current character range.
            const unsigned short old_count = _count;
            _count = c - _min + 1;
            _next.table = static_cast<generic_mtrie_t **> (
              realloc (_next.table, sizeof (generic_mtrie_t *) * _count));
            alloc_assert (_next.table);
            for (unsigned short i = old_count; i != _count; i++)
                _next.table[i] = NULL;
        } else {
            //  The new character is below the current character range.
            const unsigned short old_count = _count;
            _count = (_min + old_count) - c;
            _next.table = static_cast<generic_mtrie_t **> (
              realloc (_next.table, sizeof (generic_mtrie_t *) * _count));
            alloc_assert (_next.table);
            memmove (_next.table + _min - c, _next.table,
                     old_count * sizeof (generic_mtrie_t *));
            for (unsigned short i = 0; i != _min - c; i++)
                _next.table[i] = NULL;
            _min = c;
        }
    }

    //  If next node does not exist, create one.
    if (_count == 1) {
        if (!_next.node) {
            _next.node = new (std::nothrow) generic_mtrie_t;
            alloc_assert (_next.node);
            ++_live_nodes;
        }
        return _next.node->add_helper (prefix_ + 1, size_ - 1, pipe_);
    }
    if (!_next.table[c - _min]) {
        _next.table[c - _min] = new (std::nothrow) generic_mtrie_t;
        alloc_assert (_next.table[c - _min]);
        ++_live_nodes;
    }
    return _next.table[c - _min]->add_helper (prefix_ + 1, size_ - 1, pipe_);
}


template <typename T>
template <typename Arg>
void zmq::generic_mtrie_t<T>::rm (value_t *pipe_,
                                  void (*func_) (prefix_t data_,
                                                 size_t size_,
                                                 Arg arg_),
                                  Arg arg_,
                                  bool call_on_uniq_)
{
    unsigned char *buff = NULL;
    rm_helper (pipe_, &buff, 0, 0, func_, arg_, call_on_uniq_);
    free (buff);
}

template <typename T>
template <typename Arg>
void zmq::generic_mtrie_t<T>::rm_helper (value_t *pipe_,
                                         unsigned char **buff_,
                                         size_t buffsize_,
                                         size_t maxbuffsize_,
                                         void (*func_) (prefix_t data_,
                                                        size_t size_,
                                                        Arg arg_),
                                         Arg arg_,
                                         bool call_on_uniq_)
{
    //  Remove the subscription from this node.
    if (_pipes && _pipes->erase (pipe_)) {
        if (!call_on_uniq_ || _pipes->empty ()) {
            func_ (*buff_, buffsize_, arg_);
        }

        if (_pipes->empty ()) {
            LIBZMQ_DELETE (_pipes);
        }
    }

    //  Adjust the buffer.
    if (buffsize_ >= maxbuffsize_) {
        maxbuffsize_ = buffsize_ + 256;
        *buff_ = static_cast<unsigned char *> (realloc (*buff_, maxbuffsize_));
        alloc_assert (*buff_);
    }

    switch (_count) {
        case 0:
            //  If there are no subnodes in the trie, return.
            break;
        case 1:
            //  If there's one subnode (optimisation).

            (*buff_)[buffsize_] = _min;
            buffsize_++;
            _next.node->rm_helper (pipe_, buff_, buffsize_, maxbuffsize_, func_,
                                   arg_, call_on_uniq_);

            //  Prune the node if it was made redundant by the removal
            if (_next.node->is_redundant ()) {
                LIBZMQ_DELETE (_next.node);
                _count = 0;
                --_live_nodes;
                zmq_assert (_live_nodes == 0);
            }
            break;
        default:
            //  If there are multiple subnodes.
            rm_helper_multiple_subnodes (buff_, buffsize_, maxbuffsize_, func_,
                                         arg_, call_on_uniq_, pipe_);
            break;
    }
}

template <typename T>
template <typename Arg>
void zmq::generic_mtrie_t<T>::rm_helper_multiple_subnodes (
  unsigned char **buff_,
  size_t buffsize_,
  size_t maxbuffsize_,
  void (*func_) (prefix_t data_, size_t size_, Arg arg_),
  Arg arg_,
  bool call_on_uniq_,
  value_t *pipe_)
{
    //  New min non-null character in the node table after the removal
    unsigned char new_min = _min + _count - 1;
    //  New max non-null character in the node table after the removal
    unsigned char new_max = _min;
    for (unsigned short c = 0; c != _count; c++) {
        (*buff_)[buffsize_] = _min + c;
        if (_next.table[c]) {
            _next.table[c]->rm_helper (pipe_, buff_, buffsize_ + 1,
                                       maxbuffsize_, func_, arg_,
                                       call_on_uniq_);

            //  Prune redundant nodes from the mtrie
            if (_next.table[c]->is_redundant ()) {
                LIBZMQ_DELETE (_next.table[c]);

                zmq_assert (_live_nodes > 0);
                --_live_nodes;
            } else {
                //  The node is not redundant, so it's a candidate for being
                //  the new min/max node.
                //
                //  We loop through the node array from left to right, so the
                //  first non-null, non-redundant node encountered is the new
                //  minimum index. Conversely, the last non-redundant, non-null
                //  node encountered is the new maximum index.
                if (c + _min < new_min)
                    new_min = c + _min;
                if (c + _min > new_max)
                    new_max = c + _min;
            }
        }
    }

    zmq_assert (_count > 1);

    //  Free the node table if it's no longer used.
    switch (_live_nodes) {
        case 0:
            free (_next.table);
            _next.table = NULL;
            _count = 0;
            break;
        case 1:
            //  Compact the node table if possible

            //  If there's only one live node in the table we can
            //  switch to using the more compact single-node
            //  representation
            zmq_assert (new_min == new_max);
            zmq_assert (new_min >= _min && new_min < _min + _count);
            {
                generic_mtrie_t *node = _next.table[new_min - _min];
                zmq_assert (node);
                free (_next.table);
                _next.node = node;
            }
            _count = 1;
            _min = new_min;
            break;
        default:
            if (new_min > _min || new_max < _min + _count - 1) {
                zmq_assert (new_max - new_min + 1 > 1);

                generic_mtrie_t **old_table = _next.table;
                zmq_assert (new_min > _min || new_max < _min + _count - 1);
                zmq_assert (new_min >= _min);
                zmq_assert (new_max <= _min + _count - 1);
                zmq_assert (new_max - new_min + 1 < _count);

                _count = new_max - new_min + 1;
                _next.table = static_cast<generic_mtrie_t **> (
                  malloc (sizeof (generic_mtrie_t *) * _count));
                alloc_assert (_next.table);

                memmove (_next.table, old_table + (new_min - _min),
                         sizeof (generic_mtrie_t *) * _count);
                free (old_table);

                _min = new_min;
            }
    }
}
template <typename T>
typename zmq::generic_mtrie_t<T>::rm_result
zmq::generic_mtrie_t<T>::rm (prefix_t prefix_, size_t size_, value_t *pipe_)
{
    return rm_helper (prefix_, size_, pipe_);
}

template <typename T>
typename zmq::generic_mtrie_t<T>::rm_result zmq::generic_mtrie_t<T>::rm_helper (
  prefix_t prefix_, size_t size_, value_t *pipe_)
{
    if (!size_) {
        if (!_pipes)
            return not_found;

        typename pipes_t::size_type erased = _pipes->erase (pipe_);
        if (_pipes->empty ()) {
            zmq_assert (erased == 1);
            LIBZMQ_DELETE (_pipes);
            return last_value_removed;
        }
        return (erased == 1) ? values_remain : not_found;
    }

    const unsigned char c = *prefix_;
    if (!_count || c < _min || c >= _min + _count)
        return not_found;

    generic_mtrie_t *next_node =
      _count == 1 ? _next.node : _next.table[c - _min];

    if (!next_node)
        return not_found;

    const rm_result ret = next_node->rm_helper (prefix_ + 1, size_ - 1, pipe_);

    if (next_node->is_redundant ()) {
        LIBZMQ_DELETE (next_node);
        zmq_assert (_count > 0);

        if (_count == 1) {
            _next.node = 0;
            _count = 0;
            --_live_nodes;
            zmq_assert (_live_nodes == 0);
        } else {
            _next.table[c - _min] = 0;
            zmq_assert (_live_nodes > 1);
            --_live_nodes;

            //  Compact the table if possible
            if (_live_nodes == 1) {
                //  If there's only one live node in the table we can
                //  switch to using the more compact single-node
                //  representation
                unsigned short i;
                for (i = 0; i < _count; ++i)
                    if (_next.table[i])
                        break;

                zmq_assert (i < _count);
                _min += i;
                _count = 1;
                generic_mtrie_t *oldp = _next.table[i];
                free (_next.table);
                _next.node = oldp;
            } else if (c == _min) {
                //  We can compact the table "from the left"
                unsigned short i;
                for (i = 1; i < _count; ++i)
                    if (_next.table[i])
                        break;

                zmq_assert (i < _count);
                _min += i;
                _count -= i;
                generic_mtrie_t **old_table = _next.table;
                _next.table = static_cast<generic_mtrie_t **> (
                  malloc (sizeof (generic_mtrie_t *) * _count));
                alloc_assert (_next.table);
                memmove (_next.table, old_table + i,
                         sizeof (generic_mtrie_t *) * _count);
                free (old_table);
            } else if (c == _min + _count - 1) {
                //  We can compact the table "from the right"
                unsigned short i;
                for (i = 1; i < _count; ++i)
                    if (_next.table[_count - 1 - i])
                        break;

                zmq_assert (i < _count);
                _count -= i;
                generic_mtrie_t **old_table = _next.table;
                _next.table = static_cast<generic_mtrie_t **> (
                  malloc (sizeof (generic_mtrie_t *) * _count));
                alloc_assert (_next.table);
                memmove (_next.table, old_table,
                         sizeof (generic_mtrie_t *) * _count);
                free (old_table);
            }
        }
    }

    return ret;
}

template <typename T>
template <typename Arg>
void zmq::generic_mtrie_t<T>::match (prefix_t data_,
                                     size_t size_,
                                     void (*func_) (value_t *pipe_, Arg arg_),
                                     Arg arg_)
{
    generic_mtrie_t *current = this;
    while (true) {
        //  Signal the pipes attached to this node.
        if (current->_pipes) {
            for (typename pipes_t::iterator it = current->_pipes->begin ();
                 it != current->_pipes->end (); ++it)
                func_ (*it, arg_);
        }

        //  If we are at the end of the message, there's nothing more to match.
        if (!size_)
            break;

        //  If there are no subnodes in the trie, return.
        if (current->_count == 0)
            break;

        //  If there's one subnode (optimisation).
        if (current->_count == 1) {
            if (data_[0] != current->_min)
                break;
            current = current->_next.node;
            data_++;
            size_--;
            continue;
        }

        //  If there are multiple subnodes.
        if (data_[0] < current->_min
            || data_[0] >= current->_min + current->_count)
            break;
        if (!current->_next.table[data_[0] - current->_min])
            break;
        current = current->_next.table[data_[0] - current->_min];
        data_++;
        size_--;
    }
}

template <typename T> bool zmq::generic_mtrie_t<T>::is_redundant () const
{
    return !_pipes && _live_nodes == 0;
}


#endif
