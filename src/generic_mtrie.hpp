/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_GENERIC_MTRIE_HPP_INCLUDED__
#define __ZMQ_GENERIC_MTRIE_HPP_INCLUDED__

#include <stddef.h>
#include <set>

#include "macros.hpp"
#include "stdint.hpp"
#include "atomic_counter.hpp"

namespace zmq
{
//  Multi-trie (prefix tree). Each node in the trie is a set of pointers.
template <typename T> class generic_mtrie_t
{
  public:
    typedef T value_t;
    typedef const unsigned char *prefix_t;

    enum rm_result
    {
        not_found,
        last_value_removed,
        values_remain
    };

    generic_mtrie_t ();
    ~generic_mtrie_t ();

    //  Add key to the trie. Returns true iff no entry with the same prefix_
    //  and size_ existed before.
    bool add (prefix_t prefix_, size_t size_, value_t *value_);

    //  Remove all entries with a specific value from the trie.
    //  The call_on_uniq_ flag controls if the callback is invoked
    //  when there are no entries left on a prefix only (true)
    //  or on every removal (false). The arg_ argument is passed
    //  through to the callback function.
    template <typename Arg>
    void rm (value_t *value_,
             void (*func_) (const unsigned char *data_, size_t size_, Arg arg_),
             Arg arg_,
             bool call_on_uniq_);

    //  Removes a specific entry from the trie.
    //  Returns the result of the operation.
    rm_result rm (prefix_t prefix_, size_t size_, value_t *value_);

    //  Calls a callback function for all matching entries, i.e. any node
    //  corresponding to data_ or a prefix of it. The arg_ argument
    //  is passed through to the callback function.
    template <typename Arg>
    void match (prefix_t data_,
                size_t size_,
                void (*func_) (value_t *value_, Arg arg_),
                Arg arg_);

    //  Retrieve the number of prefixes stored in this trie (added - removed)
    //  Note this is a multithread safe function.
    uint32_t num_prefixes () const { return _num_prefixes.get (); }

  private:
    bool is_redundant () const;

    typedef std::set<value_t *> pipes_t;
    pipes_t *_pipes;

    atomic_counter_t _num_prefixes;

    unsigned char _min;
    unsigned short _count;
    unsigned short _live_nodes;
    union _next_t
    {
        class generic_mtrie_t<value_t> *node;
        class generic_mtrie_t<value_t> **table;
    } _next;

    struct iter
    {
        generic_mtrie_t<value_t> *node;
        generic_mtrie_t<value_t> *next_node;
        prefix_t prefix;
        size_t size;
        unsigned short current_child;
        unsigned char new_min;
        unsigned char new_max;
        bool processed_for_removal;
    };

    ZMQ_NON_COPYABLE_NOR_MOVABLE (generic_mtrie_t)
};
}

#endif
