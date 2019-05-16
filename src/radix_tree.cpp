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

#include "precompiled.hpp"
#include "macros.hpp"
#include "err.hpp"
#include "radix_tree.hpp"

#include <stdlib.h>
#include <string.h>

node::node (unsigned char *data) : data_ (data)
{
}

uint32_t node::refcount ()
{
    uint32_t u32;
    memcpy (&u32, data_, sizeof (u32));
    return u32;
}

void node::set_refcount (uint32_t value)
{
    memcpy (data_, &value, sizeof (value));
}

uint32_t node::prefix_length ()
{
    uint32_t u32;
    memcpy (&u32, data_ + sizeof (uint32_t), sizeof (u32));
    return u32;
}

void node::set_prefix_length (uint32_t value)
{
    memcpy (data_ + sizeof (value), &value, sizeof (value));
}

uint32_t node::edgecount ()
{
    uint32_t u32;
    memcpy (&u32, data_ + 2 * sizeof (uint32_t), sizeof (u32));
    return u32;
}

void node::set_edgecount (uint32_t value)
{
    memcpy (data_ + 2 * sizeof (value), &value, sizeof (value));
}

unsigned char *node::prefix ()
{
    return data_ + 3 * sizeof (uint32_t);
}

void node::set_prefix (const unsigned char *bytes)
{
    memcpy (prefix (), bytes, prefix_length ());
}

unsigned char *node::first_bytes ()
{
    return prefix () + prefix_length ();
}

void node::set_first_bytes (const unsigned char *bytes)
{
    memcpy (first_bytes (), bytes, edgecount ());
}

unsigned char node::first_byte_at (size_t i)
{
    zmq_assert (i < edgecount ());
    return first_bytes ()[i];
}

void node::set_first_byte_at (size_t i, unsigned char byte)
{
    zmq_assert (i < edgecount ());
    first_bytes ()[i] = byte;
}

unsigned char *node::node_ptrs ()
{
    return prefix () + prefix_length () + edgecount ();
}

void node::set_node_ptrs (const unsigned char *ptrs)
{
    memcpy (node_ptrs (), ptrs, edgecount () * sizeof (void *));
}

node node::node_at (size_t i)
{
    zmq_assert (i < edgecount ());

    unsigned char *data;
    memcpy (&data, node_ptrs () + i * sizeof (void *), sizeof (data));
    return node (data);
}

void node::set_node_at (size_t i, node n)
{
    zmq_assert (i < edgecount ());
    memcpy (node_ptrs () + i * sizeof (void *), &n.data_, sizeof (n.data_));
}

void node::set_edge_at (size_t i, unsigned char byte, node n)
{
    set_first_byte_at (i, byte);
    set_node_at (i, n);
}

bool node::operator== (node other) const
{
    return data_ == other.data_;
}

bool node::operator!= (node other) const
{
    return !(*this == other);
}

void node::resize (size_t prefix_length, size_t edgecount)
{
    size_t sz =
      3 * sizeof (uint32_t) + prefix_length + edgecount * (1 + sizeof (void *));
    unsigned char *new_data =
      static_cast<unsigned char *> (realloc (data_, sz));
    zmq_assert (new_data);
    data_ = new_data;
    set_prefix_length (static_cast<uint32_t> (prefix_length));
    set_edgecount (static_cast<uint32_t> (edgecount));
}

node make_node (size_t refs, size_t bytes, size_t edges)
{
    size_t size = 3 * sizeof (uint32_t) + bytes + edges * (1 + sizeof (void *));

    unsigned char *data = static_cast<unsigned char *> (malloc (size));
    zmq_assert (data);

    node n (data);
    n.set_refcount (static_cast<uint32_t> (refs));
    n.set_prefix_length (static_cast<uint32_t> (bytes));
    n.set_edgecount (static_cast<uint32_t> (edges));
    return n;
}

// ----------------------------------------------------------------------

zmq::radix_tree::radix_tree () : root_ (make_node (0, 0, 0)), size_ (0)
{
}

static void free_nodes (node n)
{
    for (size_t i = 0; i < n.edgecount (); ++i)
        free_nodes (n.node_at (i));
    free (n.data_);
}

zmq::radix_tree::~radix_tree ()
{
    free_nodes (root_);
}

match_result::match_result (size_t i,
                            size_t j,
                            size_t edge_index,
                            size_t gp_edge_index,
                            node current,
                            node parent,
                            node grandparent) :
    nkey (i),
    nprefix (j),
    edge_index (edge_index),
    gp_edge_index (gp_edge_index),
    current_node (current),
    parent_node (parent),
    grandparent_node (grandparent)
{
}

match_result zmq::radix_tree::match (const unsigned char *key,
                                     size_t size,
                                     bool check = false) const
{
    zmq_assert (key);

    size_t i = 0;           // Number of characters matched in key.
    size_t j = 0;           // Number of characters matched in current node.
    size_t edge_idx = 0;    // Index of outgoing edge from the parent node.
    size_t gp_edge_idx = 0; // Index of outgoing edge from grandparent.
    node current_node = root_;
    node parent_node = current_node;
    node grandparent_node = current_node;

    while (current_node.prefix_length () > 0 || current_node.edgecount () > 0) {
        for (j = 0; j < current_node.prefix_length () && i < size; ++j, ++i) {
            if (current_node.prefix ()[j] != key[i])
                break;
        }

        // Even if a prefix of the key matches and we're doing a
        // lookup, this means we've found a matching subscription.
        if (check && j == current_node.prefix_length ()
            && current_node.refcount () > 0) {
            i = size;
            break;
        }

        // There was a mismatch or we've matched the whole key, so
        // there's nothing more to do.
        if (j != current_node.prefix_length () || i == size)
            break;

        // We need to match the rest of the key. Check if there's an
        // outgoing edge from this node.
        node next_node = current_node;
        for (size_t k = 0; k < current_node.edgecount (); ++k) {
            if (current_node.first_byte_at (k) == key[i]) {
                gp_edge_idx = edge_idx;
                edge_idx = k;
                next_node = current_node.node_at (k);
                break;
            }
        }

        if (next_node == current_node)
            break; // No outgoing edge.
        grandparent_node = parent_node;
        parent_node = current_node;
        current_node = next_node;
    }

    return match_result (i, j, edge_idx, gp_edge_idx, current_node, parent_node,
                         grandparent_node);
}

bool zmq::radix_tree::add (const unsigned char *key, size_t size)
{
    match_result result = match (key, size);
    size_t i = result.nkey;
    size_t j = result.nprefix;
    size_t edge_idx = result.edge_index;
    node current_node = result.current_node;
    node parent_node = result.parent_node;

    if (i != size) {
        // Not all characters match, we might have to split the node.
        if (i == 0 || j == current_node.prefix_length ()) {
            // The mismatch is at one of the outgoing edges, so we
            // create an edge from the current node to a new leaf node
            // that has the rest of the key as the prefix.
            node key_node = make_node (1, size - i, 0);
            key_node.set_prefix (key + i);

            // Reallocate for one more edge.
            current_node.resize (current_node.prefix_length (),
                                 current_node.edgecount () + 1);

            // Make room for the new edge. We need to shift the chunk
            // of node pointers one byte to the right. Since resize()
            // increments the edgecount by 1, node_ptrs() tells us the
            // destination address. The chunk of node pointers starts
            // at one byte to the left of this destination.
            //
            // Since the regions can overlap, we use memmove.
            memmove (current_node.node_ptrs (), current_node.node_ptrs () - 1,
                     (current_node.edgecount () - 1) * sizeof (void *));

            // Add an edge to the new node.
            current_node.set_edge_at (current_node.edgecount () - 1, key[i],
                                      key_node);

            // We need to update all pointers to the current node
            // after the call to resize().
            if (current_node.prefix_length () == 0)
                root_.data_ = current_node.data_;
            else
                parent_node.set_node_at (edge_idx, current_node);
            ++size_;
            return true;
        }

        // There was a mismatch, so we need to split this node.
        //
        // Create two nodes that will be reachable from the parent.
        // One node will have the rest of the characters from the key,
        // and the other node will have the rest of the characters
        // from the current node's prefix.
        node key_node = make_node (1, size - i, 0);
        node split_node = make_node (current_node.refcount (),
                                     current_node.prefix_length () - j,
                                     current_node.edgecount ());

        // Copy the prefix chunks to the new nodes.
        key_node.set_prefix (key + i);
        split_node.set_prefix (current_node.prefix () + j);

        // Copy the current node's edges to the new node.
        split_node.set_first_bytes (current_node.first_bytes ());
        split_node.set_node_ptrs (current_node.node_ptrs ());

        // Resize the current node to accommodate a prefix comprising
        // the matched characters and 2 outgoing edges to the above
        // nodes. Set the refcount to 0 since this node doesn't hold a
        // key.
        current_node.resize (j, 2);
        current_node.set_refcount (0);

        // Add links to the new nodes. We don't need to copy the
        // prefix since resize() retains it in the current node.
        current_node.set_edge_at (0, key_node.prefix ()[0], key_node);
        current_node.set_edge_at (1, split_node.prefix ()[0], split_node);

        ++size_;
        parent_node.set_node_at (edge_idx, current_node);
        return true;
    }

    // All characters in the key match, but we still might need to split.
    if (j != current_node.prefix_length ()) {
        // All characters in the key match, but not all characters
        // from the current node's prefix match.

        // Create a node that contains the rest of the characters from
        // the current node's prefix and the outgoing edges from the
        // current node.
        node split_node = make_node (current_node.refcount (),
                                     current_node.prefix_length () - j,
                                     current_node.edgecount ());
        split_node.set_prefix (current_node.prefix () + j);
        split_node.set_first_bytes (current_node.first_bytes ());
        split_node.set_node_ptrs (current_node.node_ptrs ());

        // Resize the current node to hold only the matched characters
        // from its prefix and one edge to the new node.
        current_node.resize (j, 1);

        // Add an edge to the split node and set the refcount to 1
        // since this key wasn't inserted earlier. We don't need to
        // set the prefix because the first j bytes in the prefix are
        // preserved by resize().
        current_node.set_edge_at (0, split_node.prefix ()[0], split_node);
        current_node.set_refcount (1);

        ++size_;
        parent_node.set_node_at (edge_idx, current_node);
        return true;
    }

    zmq_assert (i == size);
    zmq_assert (j == current_node.prefix_length ());

    ++size_;
    current_node.set_refcount (current_node.refcount () + 1);
    return current_node.refcount () == 1;
}

bool zmq::radix_tree::rm (const unsigned char *key, size_t size)
{
    match_result result = match (key, size);
    size_t i = result.nkey;
    size_t j = result.nprefix;
    size_t edge_idx = result.edge_index;
    size_t gp_edge_idx = result.gp_edge_index;
    node current_node = result.current_node;
    node parent_node = result.parent_node;
    node grandparent_node = result.grandparent_node;

    if (i != size || j != current_node.prefix_length ()
        || current_node.refcount () == 0)
        return false;

    current_node.set_refcount (current_node.refcount () - 1);
    --size_;
    if (current_node.refcount () > 0)
        return false;

    // Don't delete the root node.
    if (current_node == root_)
        return true;

    size_t outgoing_edges = current_node.edgecount ();
    if (outgoing_edges > 1)
        // This node can't be merged with any other node, so there's
        // nothing more to do.
        return true;

    if (outgoing_edges == 1) {
        // Merge this node with the single child node.
        node child = current_node.node_at (0);

        // Make room for the child node's prefix and edges. We need to
        // keep the old prefix length since resize() will overwrite
        // it.
        uint32_t old_prefix_length = current_node.prefix_length ();
        current_node.resize (old_prefix_length + child.prefix_length (),
                             child.edgecount ());

        // Append the child node's prefix to the current node.
        memcpy (current_node.prefix () + old_prefix_length, child.prefix (),
                child.prefix_length ());

        // Copy the rest of child node's data to the current node.
        current_node.set_first_bytes (child.first_bytes ());
        current_node.set_node_ptrs (child.node_ptrs ());
        current_node.set_refcount (child.refcount ());

        free (child.data_);
        parent_node.set_node_at (edge_idx, current_node);
        return true;
    }

    if (parent_node.edgecount () == 2 && parent_node.refcount () == 0
        && parent_node != root_) {
        // Removing this node leaves the parent with one child.
        // If the parent doesn't hold a key or if it isn't the root,
        // we can merge it with its single child node.
        zmq_assert (edge_idx < 2);
        node other_child = parent_node.node_at (!edge_idx);

        // Make room for the child node's prefix and edges. We need to
        // keep the old prefix length since resize() will overwrite
        // it.
        uint32_t old_prefix_length = parent_node.prefix_length ();
        parent_node.resize (old_prefix_length + other_child.prefix_length (),
                            other_child.edgecount ());

        // Append the child node's prefix to the current node.
        memcpy (parent_node.prefix () + old_prefix_length,
                other_child.prefix (), other_child.prefix_length ());

        // Copy the rest of child node's data to the current node.
        parent_node.set_first_bytes (other_child.first_bytes ());
        parent_node.set_node_ptrs (other_child.node_ptrs ());
        parent_node.set_refcount (other_child.refcount ());

        free (current_node.data_);
        free (other_child.data_);
        grandparent_node.set_node_at (gp_edge_idx, parent_node);
        return true;
    }

    // This is a leaf node that doesn't leave its parent with one
    // outgoing edge. Remove the outgoing edge to this node from the
    // parent.
    zmq_assert (outgoing_edges == 0);

    // Move the first byte and node pointer to the back of the byte
    // and pointer chunks respectively.
    size_t last_idx = parent_node.edgecount () - 1;
    unsigned char last_byte = parent_node.first_byte_at (last_idx);
    node last_ptr = parent_node.node_at (last_idx);
    parent_node.set_edge_at (edge_idx, last_byte, last_ptr);

    // Move the chunk of pointers one byte to the left, effectively
    // deleting the last byte in the region of first bytes by
    // overwriting it.
    memmove (parent_node.node_ptrs () - 1, parent_node.node_ptrs (),
             parent_node.edgecount () * sizeof (void *));

    // Shrink the parent node to the new size, which "deletes" the
    // last pointer in the chunk of node pointers.
    parent_node.resize (parent_node.prefix_length (),
                        parent_node.edgecount () - 1);

    // Nothing points to this node now, so we can reclaim it.
    free (current_node.data_);

    if (parent_node.prefix_length () == 0)
        root_.data_ = parent_node.data_;
    else
        grandparent_node.set_node_at (gp_edge_idx, parent_node);
    return true;
}

bool zmq::radix_tree::check (const unsigned char *key, size_t size)
{
    if (root_.refcount () > 0)
        return true;

    match_result result = match (key, size, true);
    return result.nkey == size
           && result.nprefix == result.current_node.prefix_length ()
           && result.current_node.refcount () > 0;
}

static void
visit_keys (node n,
            unsigned char **buffer,
            size_t buffer_size,
            size_t maxbuffer_size,
            void (*func) (unsigned char *data, size_t size, void *arg),
            void *arg)
{
    if (buffer_size >= maxbuffer_size) {
        maxbuffer_size += 256;
        *buffer =
          static_cast<unsigned char *> (realloc (*buffer, maxbuffer_size));
        zmq_assert (*buffer);
    }

    for (size_t i = 0; i < n.prefix_length (); ++i)
        (*buffer)[buffer_size++] = n.prefix ()[i];
    if (n.refcount () > 0)
        func (*buffer, buffer_size, arg);
    for (size_t i = 0; i < n.edgecount (); ++i)
        visit_keys (n.node_at (i), buffer, buffer_size, maxbuffer_size, func,
                    arg);
    buffer_size -= n.prefix_length ();
}

void zmq::radix_tree::apply (
  void (*func) (unsigned char *data, size_t size, void *arg), void *arg)
{
    unsigned char *buffer = NULL;
    visit_keys (root_, &buffer, 0, 0, func, arg);
    free (buffer);
}

size_t zmq::radix_tree::size () const
{
    return size_;
}
