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
#include <vector>

node_t::node_t (unsigned char *data) : data_ (data)
{
}

uint32_t node_t::refcount ()
{
    uint32_t u32;
    memcpy (&u32, data_, sizeof (u32));
    return u32;
}

void node_t::set_refcount (uint32_t value)
{
    memcpy (data_, &value, sizeof (value));
}

uint32_t node_t::prefix_length ()
{
    uint32_t u32;
    memcpy (&u32, data_ + sizeof (uint32_t), sizeof (u32));
    return u32;
}

void node_t::set_prefix_length (uint32_t value)
{
    memcpy (data_ + sizeof (value), &value, sizeof (value));
}

uint32_t node_t::edgecount ()
{
    uint32_t u32;
    memcpy (&u32, data_ + 2 * sizeof (uint32_t), sizeof (u32));
    return u32;
}

void node_t::set_edgecount (uint32_t value)
{
    memcpy (data_ + 2 * sizeof (value), &value, sizeof (value));
}

unsigned char *node_t::prefix ()
{
    return data_ + 3 * sizeof (uint32_t);
}

void node_t::set_prefix (const unsigned char *bytes)
{
    memcpy (prefix (), bytes, prefix_length ());
}

unsigned char *node_t::first_bytes ()
{
    return prefix () + prefix_length ();
}

void node_t::set_first_bytes (const unsigned char *bytes)
{
    memcpy (first_bytes (), bytes, edgecount ());
}

unsigned char node_t::first_byte_at (size_t index)
{
    zmq_assert (index < edgecount ());
    return first_bytes ()[index];
}

void node_t::set_first_byte_at (size_t index, unsigned char byte)
{
    zmq_assert (index < edgecount ());
    first_bytes ()[index] = byte;
}

unsigned char *node_t::node_pointers ()
{
    return prefix () + prefix_length () + edgecount ();
}

void node_t::set_node_pointers (const unsigned char *pointers)
{
    memcpy (node_pointers (), pointers, edgecount () * sizeof (void *));
}

node_t node_t::node_at (size_t index)
{
    zmq_assert (index < edgecount ());

    unsigned char *data;
    memcpy (&data, node_pointers () + index * sizeof (void *), sizeof (data));
    return node_t (data);
}

void node_t::set_node_at (size_t index, node_t node)
{
    zmq_assert (index < edgecount ());
    memcpy (node_pointers () + index * sizeof (void *), &node.data_,
            sizeof (node.data_));
}

void node_t::set_edge_at (size_t index, unsigned char first_byte, node_t node)
{
    set_first_byte_at (index, first_byte);
    set_node_at (index, node);
}

bool node_t::operator== (node_t other) const
{
    return data_ == other.data_;
}

bool node_t::operator!= (node_t other) const
{
    return !(*this == other);
}

void node_t::resize (size_t prefix_length, size_t edgecount)
{
    size_t node_size =
      3 * sizeof (uint32_t) + prefix_length + edgecount * (1 + sizeof (void *));
    unsigned char *new_data =
      static_cast<unsigned char *> (realloc (data_, node_size));
    zmq_assert (new_data);
    data_ = new_data;
    set_prefix_length (static_cast<uint32_t> (prefix_length));
    set_edgecount (static_cast<uint32_t> (edgecount));
}

node_t make_node (size_t refcount, size_t prefix_length, size_t edgecount)
{
    size_t node_size =
      3 * sizeof (uint32_t) + prefix_length + edgecount * (1 + sizeof (void *));

    unsigned char *data = static_cast<unsigned char *> (malloc (node_size));
    zmq_assert (data);

    node_t node (data);
    node.set_refcount (static_cast<uint32_t> (refcount));
    node.set_prefix_length (static_cast<uint32_t> (prefix_length));
    node.set_edgecount (static_cast<uint32_t> (edgecount));
    return node;
}

// ----------------------------------------------------------------------

zmq::radix_tree::radix_tree () : root_ (make_node (0, 0, 0)), size_ (0)
{
}

static void free_nodes (node_t node)
{
    for (size_t i = 0; i < node.edgecount (); ++i)
        free_nodes (node.node_at (i));
    free (node.data_);
}

zmq::radix_tree::~radix_tree ()
{
    free_nodes (root_);
}

match_result_t::match_result_t (size_t key_bytes_matched,
                                size_t prefix_bytes_matched,
                                size_t edge_index,
                                size_t parent_edge_index,
                                node_t current,
                                node_t parent,
                                node_t grandparent) :
    key_bytes_matched (key_bytes_matched),
    prefix_bytes_matched (prefix_bytes_matched),
    edge_index (edge_index),
    parent_edge_index (parent_edge_index),
    current_node (current),
    parent_node (parent),
    grandparent_node (grandparent)
{
}

match_result_t zmq::radix_tree::match (const unsigned char *key,
                                       size_t key_size,
                                       bool is_lookup = false) const
{
    zmq_assert (key);

    // Node we're currently at in the traversal and its predecessors.
    node_t current_node = root_;
    node_t parent_node = current_node;
    node_t grandparent_node = current_node;
    // Index of the next byte to match in the key.
    size_t key_byte_index = 0;
    // Index of the next byte to match in the current node's prefix.
    size_t prefix_byte_index = 0;
    // Index of the edge from parent to current node.
    size_t edge_index = 0;
    // Index of the edge from grandparent to parent.
    size_t parent_edge_index = 0;

    while (current_node.prefix_length () > 0 || current_node.edgecount () > 0) {
        for (prefix_byte_index = 0;
             prefix_byte_index < current_node.prefix_length ()
             && key_byte_index < key_size;
             ++prefix_byte_index, ++key_byte_index) {
            if (current_node.prefix ()[prefix_byte_index]
                != key[key_byte_index])
                break;
        }

        // Even if a prefix of the key matches and we're doing a
        // lookup, this means we've found a matching subscription.
        if (is_lookup && prefix_byte_index == current_node.prefix_length ()
            && current_node.refcount () > 0) {
            key_byte_index = key_size;
            break;
        }

        // There was a mismatch or we've matched the whole key, so
        // there's nothing more to do.
        if (prefix_byte_index != current_node.prefix_length ()
            || key_byte_index == key_size)
            break;

        // We need to match the rest of the key. Check if there's an
        // outgoing edge from this node.
        node_t next_node = current_node;
        for (size_t i = 0; i < current_node.edgecount (); ++i) {
            if (current_node.first_byte_at (i) == key[key_byte_index]) {
                parent_edge_index = edge_index;
                edge_index = i;
                next_node = current_node.node_at (i);
                break;
            }
        }

        if (next_node == current_node)
            break; // No outgoing edge.
        grandparent_node = parent_node;
        parent_node = current_node;
        current_node = next_node;
    }

    return match_result_t (key_byte_index, prefix_byte_index, edge_index,
                           parent_edge_index, current_node, parent_node,
                           grandparent_node);
}

bool zmq::radix_tree::add (const unsigned char *key, size_t key_size)
{
    match_result_t match_result = match (key, key_size);
    size_t key_bytes_matched = match_result.key_bytes_matched;
    size_t prefix_bytes_matched = match_result.prefix_bytes_matched;
    size_t edge_index = match_result.edge_index;
    node_t current_node = match_result.current_node;
    node_t parent_node = match_result.parent_node;

    if (key_bytes_matched != key_size) {
        // Not all characters match, we might have to split the node.
        if (key_bytes_matched == 0
            || prefix_bytes_matched == current_node.prefix_length ()) {
            // The mismatch is at one of the outgoing edges, so we
            // create an edge from the current node to a new leaf node
            // that has the rest of the key as the prefix.
            node_t key_node = make_node (1, key_size - key_bytes_matched, 0);
            key_node.set_prefix (key + key_bytes_matched);

            // Reallocate for one more edge.
            current_node.resize (current_node.prefix_length (),
                                 current_node.edgecount () + 1);

            // Make room for the new edge. We need to shift the chunk
            // of node pointers one byte to the right. Since resize()
            // increments the edgecount by 1, node_pointers() tells us the
            // destination address. The chunk of node pointers starts
            // at one byte to the left of this destination.
            //
            // Since the regions can overlap, we use memmove.
            memmove (current_node.node_pointers (),
                     current_node.node_pointers () - 1,
                     (current_node.edgecount () - 1) * sizeof (void *));

            // Add an edge to the new node.
            current_node.set_edge_at (current_node.edgecount () - 1,
                                      key[key_bytes_matched], key_node);

            // We need to update all pointers to the current node
            // after the call to resize().
            if (current_node.prefix_length () == 0)
                root_.data_ = current_node.data_;
            else
                parent_node.set_node_at (edge_index, current_node);
            ++size_;
            return true;
        }

        // There was a mismatch, so we need to split this node.
        //
        // Create two nodes that will be reachable from the parent.
        // One node will have the rest of the characters from the key,
        // and the other node will have the rest of the characters
        // from the current node's prefix.
        node_t key_node = make_node (1, key_size - key_bytes_matched, 0);
        node_t split_node =
          make_node (current_node.refcount (),
                     current_node.prefix_length () - prefix_bytes_matched,
                     current_node.edgecount ());

        // Copy the prefix chunks to the new nodes.
        key_node.set_prefix (key + key_bytes_matched);
        split_node.set_prefix (current_node.prefix () + prefix_bytes_matched);

        // Copy the current node's edges to the new node.
        split_node.set_first_bytes (current_node.first_bytes ());
        split_node.set_node_pointers (current_node.node_pointers ());

        // Resize the current node to accommodate a prefix comprising
        // the matched characters and 2 outgoing edges to the above
        // nodes. Set the refcount to 0 since this node doesn't hold a
        // key.
        current_node.resize (prefix_bytes_matched, 2);
        current_node.set_refcount (0);

        // Add links to the new nodes. We don't need to copy the
        // prefix since resize() retains it in the current node.
        current_node.set_edge_at (0, key_node.prefix ()[0], key_node);
        current_node.set_edge_at (1, split_node.prefix ()[0], split_node);

        ++size_;
        parent_node.set_node_at (edge_index, current_node);
        return true;
    }

    // All characters in the key match, but we still might need to split.
    if (prefix_bytes_matched != current_node.prefix_length ()) {
        // All characters in the key match, but not all characters
        // from the current node's prefix match.

        // Create a node that contains the rest of the characters from
        // the current node's prefix and the outgoing edges from the
        // current node.
        node_t split_node =
          make_node (current_node.refcount (),
                     current_node.prefix_length () - prefix_bytes_matched,
                     current_node.edgecount ());
        split_node.set_prefix (current_node.prefix () + prefix_bytes_matched);
        split_node.set_first_bytes (current_node.first_bytes ());
        split_node.set_node_pointers (current_node.node_pointers ());

        // Resize the current node to hold only the matched characters
        // from its prefix and one edge to the new node.
        current_node.resize (prefix_bytes_matched, 1);

        // Add an edge to the split node and set the refcount to 1
        // since this key wasn't inserted earlier. We don't need to
        // set the prefix because the first `prefix_bytes_matched` bytes
        // in the prefix are preserved by resize().
        current_node.set_edge_at (0, split_node.prefix ()[0], split_node);
        current_node.set_refcount (1);

        ++size_;
        parent_node.set_node_at (edge_index, current_node);
        return true;
    }

    zmq_assert (key_bytes_matched == key_size);
    zmq_assert (prefix_bytes_matched == current_node.prefix_length ());

    ++size_;
    current_node.set_refcount (current_node.refcount () + 1);
    return current_node.refcount () == 1;
}

bool zmq::radix_tree::rm (const unsigned char *key, size_t key_size)
{
    match_result_t match_result = match (key, key_size);
    size_t key_bytes_matched = match_result.key_bytes_matched;
    size_t prefix_bytes_matched = match_result.prefix_bytes_matched;
    size_t edge_index = match_result.edge_index;
    size_t parent_edge_index = match_result.parent_edge_index;
    node_t current_node = match_result.current_node;
    node_t parent_node = match_result.parent_node;
    node_t grandparent_node = match_result.grandparent_node;

    if (key_bytes_matched != key_size
        || prefix_bytes_matched != current_node.prefix_length ()
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
        node_t child = current_node.node_at (0);

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
        current_node.set_node_pointers (child.node_pointers ());
        current_node.set_refcount (child.refcount ());

        free (child.data_);
        parent_node.set_node_at (edge_index, current_node);
        return true;
    }

    if (parent_node.edgecount () == 2 && parent_node.refcount () == 0
        && parent_node != root_) {
        // Removing this node leaves the parent with one child.
        // If the parent doesn't hold a key or if it isn't the root,
        // we can merge it with its single child node.
        zmq_assert (edge_index < 2);
        node_t other_child = parent_node.node_at (!edge_index);

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
        parent_node.set_node_pointers (other_child.node_pointers ());
        parent_node.set_refcount (other_child.refcount ());

        free (current_node.data_);
        free (other_child.data_);
        grandparent_node.set_node_at (parent_edge_index, parent_node);
        return true;
    }

    // This is a leaf node that doesn't leave its parent with one
    // outgoing edge. Remove the outgoing edge to this node from the
    // parent.
    zmq_assert (outgoing_edges == 0);

    // Replace the edge to the current node with the last edge. An
    // edge consists of a byte and a pointer to the next node. First
    // replace the byte.
    size_t last_index = parent_node.edgecount () - 1;
    unsigned char last_byte = parent_node.first_byte_at (last_index);
    node_t last_node = parent_node.node_at (last_index);
    parent_node.set_edge_at (edge_index, last_byte, last_node);

    // Move the chunk of pointers one byte to the left, effectively
    // deleting the last byte in the region of first bytes by
    // overwriting it.
    memmove (parent_node.node_pointers () - 1, parent_node.node_pointers (),
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
        grandparent_node.set_node_at (parent_edge_index, parent_node);
    return true;
}

bool zmq::radix_tree::check (const unsigned char *key, size_t key_size)
{
    if (root_.refcount () > 0)
        return true;

    match_result_t match_result = match (key, key_size, true);
    return match_result.key_bytes_matched == key_size
           && match_result.prefix_bytes_matched
                == match_result.current_node.prefix_length ()
           && match_result.current_node.refcount () > 0;
}

static void
visit_keys (node_t node,
            std::vector<unsigned char> &buffer,
            void (*func) (unsigned char *data, size_t size, void *arg),
            void *arg)
{
    for (size_t i = 0; i < node.prefix_length (); ++i)
        buffer.push_back (node.prefix ()[i]);

    if (node.refcount () > 0) {
        zmq_assert (!buffer.empty ());
        func (&buffer[0], buffer.size (), arg);
    }

    for (size_t i = 0; i < node.edgecount (); ++i)
        visit_keys (node.node_at (i), buffer, func, arg);
    for (size_t i = 0; i < node.prefix_length (); ++i)
        buffer.pop_back ();
}

void zmq::radix_tree::apply (
  void (*func) (unsigned char *data, size_t size, void *arg), void *arg)
{
    if (root_.refcount () > 0)
        func (NULL, 0, arg); // Root node is always empty.

    std::vector<unsigned char> buffer;
    for (size_t i = 0; i < root_.edgecount (); ++i)
        visit_keys (root_.node_at (i), buffer, func, arg);
}

size_t zmq::radix_tree::size () const
{
    return size_;
}
