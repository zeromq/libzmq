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

#ifndef RADIX_TREE_HPP
#define RADIX_TREE_HPP

#include <stddef.h>

#include "stdint.hpp"

// Wrapper type for a node's data layout.
//
// There are 3 32-bit unsigned integers that act as a header. These
// integers represent the following values in this order:
//
// (1) The reference count of the key held by the node. This is 0 if
// the node doesn't hold a key.
//
// (2) The number of characters in the node's prefix. The prefix is a
// part of one or more keys in the tree, e.g. the prefix of each node
// in a trie consists of a single character.
//
// (3) The number of outgoing edges from this node.
//
// The rest of the layout consists of 3 chunks in this order:
//
// (1) The node's prefix as a sequence of one or more bytes. The root
// node always has an empty prefix, unlike other nodes in the tree.
//
// (2) The first byte of the prefix of each of this node's children.
//
// (3) The pointer to each child node.
//
// The link to each child is looked up using its index, e.g. the child
// with index 0 will have its first byte and node pointer at the start
// of the chunk of first bytes and node pointers respectively.
struct node_t
{
    unsigned char *data_;

    explicit node_t (unsigned char *data);

    bool operator== (node_t other) const;
    bool operator!= (node_t other) const;

    inline uint32_t refcount ();
    inline uint32_t prefix_length ();
    inline uint32_t edgecount ();
    inline unsigned char *prefix ();
    inline unsigned char *first_bytes ();
    inline unsigned char first_byte_at (size_t index);
    inline unsigned char *node_pointers ();
    inline node_t node_at (size_t index);
    inline void set_refcount (uint32_t value);
    inline void set_prefix_length (uint32_t value);
    inline void set_edgecount (uint32_t value);
    inline void set_prefix (const unsigned char *prefix);
    inline void set_first_bytes (const unsigned char *bytes);
    inline void set_first_byte_at (size_t index, unsigned char byte);
    inline void set_node_pointers (const unsigned char *pointers);
    inline void set_node_at (size_t index, node_t node);
    inline void
    set_edge_at (size_t index, unsigned char first_byte, node_t node);
    void resize (size_t prefix_length, size_t edgecount);
};

node_t make_node (size_t refcount, size_t prefix_length, size_t edgecount);

struct match_result_t
{
    size_t key_bytes_matched;
    size_t prefix_bytes_matched;
    size_t edge_index;
    size_t parent_edge_index;
    node_t current_node;
    node_t parent_node;
    node_t grandparent_node;

    match_result_t (size_t key_bytes_matched,
                    size_t prefix_bytes_matched,
                    size_t edge_index,
                    size_t parent_edge_index,
                    node_t current,
                    node_t parent,
                    node_t grandparent);
};

namespace zmq
{
class radix_tree
{
  public:
    radix_tree ();
    ~radix_tree ();

    //  Add key to the tree. Returns true if this was a new key rather
    //  than a duplicate.
    bool add (const unsigned char *key_, size_t key_size_);

    //  Remove key from the tree. Returns true if the item is actually
    //  removed from the tree.
    bool rm (const unsigned char *key_, size_t key_size_);

    //  Check whether particular key is in the tree.
    bool check (const unsigned char *key_, size_t key_size_);

    //  Apply the function supplied to each key in the tree.
    void apply (void (*func_) (unsigned char *data, size_t size, void *arg),
                void *arg_);

    size_t size () const;

  private:
    inline match_result_t
    match (const unsigned char *key, size_t key_size, bool is_lookup) const;

    node_t root_;
    size_t size_;
};
}

#endif
