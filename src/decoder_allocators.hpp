/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_DECODER_ALLOCATORS_HPP_INCLUDED__
#define __ZMQ_DECODER_ALLOCATORS_HPP_INCLUDED__

#include <cstddef>
#include <cstdlib>

#include "atomic_counter.hpp"
#include "msg.hpp"
#include "err.hpp"

namespace zmq
{
// Static buffer policy.
class c_single_allocator
{
  public:
    explicit c_single_allocator (std::size_t bufsize_) :
        _buf_size (bufsize_),
        _buf (static_cast<unsigned char *> (std::malloc (_buf_size)))
    {
        alloc_assert (_buf);
    }

    ~c_single_allocator () { std::free (_buf); }

    unsigned char *allocate () { return _buf; }

    void deallocate () {}

    std::size_t size () const { return _buf_size; }

    //  This buffer is fixed, size must not be changed
    void resize (std::size_t new_size_) { LIBZMQ_UNUSED (new_size_); }

  private:
    std::size_t _buf_size;
    unsigned char *_buf;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (c_single_allocator)
};

// This allocator allocates a reference counted buffer which is used by v2_decoder_t
// to use zero-copy msg::init_data to create messages with memory from this buffer as
// data storage.
//
// The buffer is allocated with a reference count of 1 to make sure that is is alive while
// decoding messages. Otherwise, it is possible that e.g. the first message increases the count
// from zero to one, gets passed to the user application, processed in the user thread and deleted
// which would then deallocate the buffer. The drawback is that the buffer may be allocated longer
// than necessary because it is only deleted when allocate is called the next time.
class shared_message_memory_allocator
{
  public:
    explicit shared_message_memory_allocator (std::size_t bufsize_);

    // Create an allocator for a maximum number of messages
    shared_message_memory_allocator (std::size_t bufsize_,
                                     std::size_t max_messages_);

    ~shared_message_memory_allocator ();

    // Allocate a new buffer
    //
    // This releases the current buffer to be bound to the lifetime of the messages
    // created on this buffer.
    unsigned char *allocate ();

    // force deallocation of buffer.
    void deallocate ();

    // Give up ownership of the buffer. The buffer's lifetime is now coupled to
    // the messages constructed on top of it.
    unsigned char *release ();

    void inc_ref ();

    static void call_dec_ref (void *, void *hint_);

    std::size_t size () const;

    // Return pointer to the first message data byte.
    unsigned char *data ();

    // Return pointer to the first byte of the buffer.
    unsigned char *buffer () { return _buf; }

    void resize (std::size_t new_size_) { _buf_size = new_size_; }

    zmq::msg_t::content_t *provide_content () { return _msg_content; }

    void advance_content () { _msg_content++; }

  private:
    void clear ();

    unsigned char *_buf;
    std::size_t _buf_size;
    const std::size_t _max_size;
    zmq::msg_t::content_t *_msg_content;
    std::size_t _max_counters;
};
}

#endif
