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

#include <stdlib.h>
#include <string.h>
#include <cmath>

#include "platform.hpp"
#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include "v2_protocol.hpp"
#include "v2_decoder.hpp"
#include "likely.hpp"
#include "wire.hpp"
#include "err.hpp"

zmq::shared_message_memory_allocator::shared_message_memory_allocator(size_t bufsize_):
    buf(NULL),
    bufsize( 0 ),
    max_size( bufsize_ ),
    msg_refcnt( NULL )
{

}

zmq::shared_message_memory_allocator::~shared_message_memory_allocator()
{
    if (buf) {
        deallocate();
    }
}

unsigned char* zmq::shared_message_memory_allocator::allocate()
{
    if (buf)
    {
        // release reference count to couple lifetime to messages
        zmq::atomic_counter_t *c = reinterpret_cast<zmq::atomic_counter_t *>(buf);

        // if refcnt drops to 0, there are no message using the buffer
        // because either all messages have been closed or only vsm-messages
        // were created
        if (c->sub(1)) {
            // buffer is still in use as message data. "Release" it and create a new one
            // release pointer because we are going to create a new buffer
            release();
        }
    }

    // if buf != NULL it is not used by any message so we can re-use it for the next run
    if (!buf) {
        // allocate memory for reference counters together with reception buffer
        size_t const maxCounters = std::ceil( (double)max_size / (double)msg_t::max_vsm_size);
        size_t const allocationsize = max_size + sizeof(zmq::atomic_counter_t) + maxCounters * sizeof(zmq::atomic_counter_t);

        buf = (unsigned char *) malloc(allocationsize);
        alloc_assert (buf);

        new(buf) atomic_counter_t(1);
    }
    else
    {
        // release reference count to couple lifetime to messages
        zmq::atomic_counter_t *c = reinterpret_cast<zmq::atomic_counter_t *>(buf);
        c->set(1);
    }

    bufsize = max_size;
    msg_refcnt = reinterpret_cast<zmq::atomic_counter_t*>( buf + sizeof(atomic_counter_t) + max_size );
    return buf + sizeof( zmq::atomic_counter_t);
}

void zmq::shared_message_memory_allocator::deallocate()
{
    free(buf);
    buf = NULL;
    bufsize = 0;
    msg_refcnt = NULL;
}

unsigned char* zmq::shared_message_memory_allocator::release()
{
    unsigned char* b = buf;
    buf = NULL;
    bufsize = 0;
    msg_refcnt = NULL;

    return b;
}

void zmq::shared_message_memory_allocator::inc_ref()
{
    ((zmq::atomic_counter_t*)buf)->add(1);
}

void zmq::shared_message_memory_allocator::call_dec_ref(void*, void* hint) {
    zmq_assert( hint );
    unsigned char* buf = static_cast<unsigned char*>(hint);
    zmq::atomic_counter_t *c = reinterpret_cast<zmq::atomic_counter_t *>(buf);

    if (!c->sub(1)) {
        c->~atomic_counter_t();
        free(buf);
        buf = NULL;
    }
}


size_t zmq::shared_message_memory_allocator::size() const
{
    return bufsize;
}

unsigned char* zmq::shared_message_memory_allocator::data()
{
    return buf + sizeof(zmq::atomic_counter_t);
}

zmq::v2_decoder_t::v2_decoder_t (size_t bufsize_, int64_t maxmsgsize_) :
    shared_message_memory_allocator( bufsize_),
    decoder_base_t <v2_decoder_t, shared_message_memory_allocator> (this),
    msg_flags (0),
    maxmsgsize (maxmsgsize_)
{
    int rc = in_progress.init ();
    errno_assert (rc == 0);

    //  At the beginning, read one byte and go to flags_ready state.
    next_step (tmpbuf, 1, &v2_decoder_t::flags_ready);
}

zmq::v2_decoder_t::~v2_decoder_t ()
{
    int rc = in_progress.close ();
    errno_assert (rc == 0);
}

int zmq::v2_decoder_t::flags_ready (unsigned char const*)
{
    msg_flags = 0;
    if (tmpbuf [0] & v2_protocol_t::more_flag)
        msg_flags |= msg_t::more;
    if (tmpbuf [0] & v2_protocol_t::command_flag)
        msg_flags |= msg_t::command;

    //  The payload length is either one or eight bytes,
    //  depending on whether the 'large' bit is set.
    if (tmpbuf [0] & v2_protocol_t::large_flag)
        next_step (tmpbuf, 8, &v2_decoder_t::eight_byte_size_ready);
    else
        next_step (tmpbuf, 1, &v2_decoder_t::one_byte_size_ready);

    return 0;
}

int zmq::v2_decoder_t::one_byte_size_ready (unsigned char const* read_from)
{
    return size_ready(tmpbuf[0], read_from);
}

int zmq::v2_decoder_t::eight_byte_size_ready (unsigned char const* read_from) {
    //  The payload size is encoded as 64-bit unsigned integer.
    //  The most significant byte comes first.
    const uint64_t msg_size = get_uint64(tmpbuf);

    return size_ready(msg_size, read_from);
}

int zmq::v2_decoder_t::size_ready(uint64_t msg_size, unsigned char const* read_pos) {
    //  Message size must not exceed the maximum allowed size.
    if (maxmsgsize >= 0)
        if (unlikely (msg_size > static_cast <uint64_t> (maxmsgsize))) {
            errno = EMSGSIZE;
            return -1;
        }

    //  Message size must fit into size_t data type.
    if (unlikely (msg_size != static_cast <size_t> (msg_size))) {
        errno = EMSGSIZE;
        return -1;
    }

    //  in_progress is initialised at this point so in theory we should
    //  close it before calling init_size, however, it's a 0-byte
    //  message and thus we can treat it as uninitialised.
    int rc = -1;

    // the current message can exceed the current buffer. We have to copy the buffer
    // data into a new message and complete it in the next receive.

    if (unlikely ((unsigned char*)read_pos + msg_size > (data() + size())))
    {
        // a new message has started, but the size would exceed the pre-allocated arena
        // this happens everytime when a message does not fit completely into the buffer
        rc = in_progress.init_size (static_cast <size_t> (msg_size));
    }
    else
    {
        // construct message using n bytes from the buffer as storage
        // increase buffer ref count
        // if the message will be a large message, pass a valid refcnt memory location as well
        rc = in_progress.init( (unsigned char*)read_pos, msg_size,
                               shared_message_memory_allocator::call_dec_ref, buffer(),
                               create_refcnt() );

        // For small messages, data has been copied and refcount does not have to be increased
        if (in_progress.is_zcmsg())
        {
            inc_ref();
        }
    }

    if (unlikely (rc)) {
        errno_assert (errno == ENOMEM);
        rc = in_progress.init ();
        errno_assert (rc == 0);
        errno = ENOMEM;
        return -1;
    }

    in_progress.set_flags (msg_flags);
    // this sets read_pos to
    // the message data address if the data needs to be copied
    // for small message / messages exceeding the current buffer
    // or
    // to the current start address in the buffer because the message
    // was constructed to use n bytes from the address passed as argument
    next_step (in_progress.data (), in_progress.size (),
        &v2_decoder_t::message_ready);

    return 0;
}

int zmq::v2_decoder_t::message_ready (unsigned char const*)
{
    //  Message is completely read. Signal this to the caller
    //  and prepare to decode next message.
    next_step (tmpbuf, 1, &v2_decoder_t::flags_ready);
    return 1;
}
