/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_TRIE_HPP_INCLUDED__
#define __ZMQ_TRIE_HPP_INCLUDED__

#include <stddef.h>

#include "macros.hpp"
#include "stdint.hpp"
#include "atomic_counter.hpp"

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
    bool check (const unsigned char *data_, size_t size_) const;

    //  Apply the function supplied to each subscription in the trie.
    void apply (void (*func_) (unsigned char *data_, size_t size_, void *arg_),
                void *arg_);

  private:
    void apply_helper (unsigned char **buff_,
                       size_t buffsize_,
                       size_t maxbuffsize_,
                       void (*func_) (unsigned char *data_,
                                      size_t size_,
                                      void *arg_),
                       void *arg_) const;
    bool is_redundant () const;

    uint32_t _refcnt;
    unsigned char _min;
    unsigned short _count;
    unsigned short _live_nodes;
    union
    {
        class trie_t *node;
        class trie_t **table;
    } _next;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (trie_t)
};


// lightweight wrapper around trie_t adding tracking of total number of prefixes
class trie_with_size_t
{
  public:
    trie_with_size_t () {}
    ~trie_with_size_t () {}

    bool add (unsigned char *prefix_, size_t size_)
    {
        if (_trie.add (prefix_, size_)) {
            _num_prefixes.add (1);
            return true;
        } else
            return false;
    }

    bool rm (unsigned char *prefix_, size_t size_)
    {
        if (_trie.rm (prefix_, size_)) {
            _num_prefixes.sub (1);
            return true;
        } else
            return false;
    }

    bool check (const unsigned char *data_, size_t size_) const
    {
        return _trie.check (data_, size_);
    }

    void apply (void (*func_) (unsigned char *data_, size_t size_, void *arg_),
                void *arg_)
    {
        _trie.apply (func_, arg_);
    }

    //  Retrieve the number of prefixes stored in this trie (added - removed)
    //  Note this is a multithread safe function.
    uint32_t num_prefixes () const { return _num_prefixes.get (); }

  private:
    atomic_counter_t _num_prefixes;
    trie_t _trie;
};

}

#endif
