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

#ifndef __ZMQ_V2_DECODER_HPP_INCLUDED__
#define __ZMQ_V2_DECODER_HPP_INCLUDED__

#include "decoder.hpp"

namespace zmq
{
    // This allocater allocates a reference counted buffer which is used by v2_decoder_t
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
        shared_message_memory_allocator(size_t bufsize_);

        ~shared_message_memory_allocator();

        // Allocate a new buffer
        //
        // This releases the current buffer to be bound to the lifetime of the messages
        // created on this bufer.
        unsigned char* allocate();

        // force deallocation of buffer.
        void deallocate();

        // Give up ownership of the buffer. The buffer's lifetime is now coupled to
        // the messages constructed on top of it.
        unsigned char* release();

        void reset(unsigned char* b);

        void inc_ref();

        static void call_dec_ref(void*, void* buffer);

        size_t size() const;

        // Return pointer to the first message data byte.
        unsigned char* data();

        // Return pointer to the first byte of the buffer.
        unsigned char* buffer()
        {
            return buf;
        }

        void resize(size_t new_size)
        {
            bufsize = new_size;
        }

    private:
        unsigned char* buf;
        size_t bufsize;
        size_t maxsize;
        zmq::atomic_counter_t* msg_refcnt;
    };

    //  Decoder for ZMTP/2.x framing protocol. Converts data stream into messages.
    //  The class has to inherit from shared_message_memory_allocator because
    //  the base class calls allocate in its constructor.
    class v2_decoder_t :
            // inherit first from allocator to ensure that it is constructed before decoder_base_t
            public shared_message_memory_allocator,
            public decoder_base_t <v2_decoder_t, shared_message_memory_allocator>
    {
    public:
        v2_decoder_t (size_t bufsize_, int64_t maxmsgsize_);
        virtual ~v2_decoder_t ();

        //  i_decoder interface.
        virtual msg_t *msg () { return &in_progress; }

    private:

        int flags_ready (unsigned char const*);
        int one_byte_size_ready (unsigned char const*);
        int eight_byte_size_ready (unsigned char const*);
        int message_ready (unsigned char const*);

        int size_ready(uint64_t size_, unsigned char const*);

        unsigned char tmpbuf [8];
        unsigned char msg_flags;
        msg_t in_progress;

        const int64_t maxmsgsize;

        v2_decoder_t (const v2_decoder_t&);
        void operator = (const v2_decoder_t&);
    };

}

#endif
