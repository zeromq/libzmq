/* SPDX-License-Identifier: MPL-2.0 */

#ifndef RADIX_TREE_HPP
#define RADIX_TREE_HPP

#include <stddef.h>

#include "stdint.hpp"
#include "atomic_counter.hpp"

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
    explicit node_t (unsigned char *data_);

    bool operator== (node_t other_) const;
    bool operator!= (node_t other_) const;

    uint32_t refcount ();
    uint32_t prefix_length ();
    uint32_t edgecount ();
    unsigned char *prefix ();
    unsigned char *first_bytes ();
    unsigned char first_byte_at (size_t index_);
    unsigned char *node_pointers ();
    node_t node_at (size_t index_);
    void set_refcount (uint32_t value_);
    void set_prefix_length (uint32_t value_);
    void set_edgecount (uint32_t value_);
    void set_prefix (const unsigned char *bytes_);
    void set_first_bytes (const unsigned char *bytes_);
    void set_first_byte_at (size_t index_, unsigned char byte_);
    void set_node_pointers (const unsigned char *pointers_);
    void set_node_at (size_t index_, node_t node_);
    void set_edge_at (size_t index_, unsigned char first_byte_, node_t node_);
    void resize (size_t prefix_length_, size_t edgecount_);

    unsigned char *_data;
};

node_t make_node (size_t refcount_, size_t prefix_length_, size_t edgecount_);

struct match_result_t
{
    match_result_t (size_t key_bytes_matched_,
                    size_t prefix_bytes_matched_,
                    size_t edge_index_,
                    size_t parent_edge_index_,
                    node_t current_,
                    node_t parent_,
                    node_t grandparent);

    size_t _key_bytes_matched;
    size_t _prefix_bytes_matched;
    size_t _edge_index;
    size_t _parent_edge_index;
    node_t _current_node;
    node_t _parent_node;
    node_t _grandparent_node;
};

namespace zmq
{
class radix_tree_t
{
  public:
    radix_tree_t ();
    ~radix_tree_t ();

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

    //  Retrieve size of the radix tree. Note this is a multithread safe function.
    size_t size () const;

  private:
    match_result_t
    match (const unsigned char *key_, size_t key_size_, bool is_lookup_) const;

    node_t _root;
    atomic_counter_t _size;
};
}

#endif
