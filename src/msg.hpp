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

#ifndef __ZMQ_MSG_HPP_INCLUDE__
#define __ZMQ_MSG_HPP_INCLUDE__

#include <stddef.h>
#include <stdio.h>

#include "config.hpp"
#include "atomic_counter.hpp"
#include "metadata.hpp"

//  Signature for free function to deallocate the message content.
//  Note that it has to be declared as "C" so that it is the same as
//  zmq_free_fn defined in zmq.h.
extern "C"
{
    typedef void (msg_free_fn) (void *data, void *hint);
}

namespace zmq
{

    //  Note that this structure needs to be explicitly constructed
    //  (init functions) and destructed (close function).

    class msg_t
    {
    public:

        //  Message flags.
        enum
        {
            more = 1,           //  Followed by more parts
            command = 2,        //  Command frame (see ZMTP spec)
            credential = 32,
            identity = 64,
            shared = 128
        };

        bool check ();
        int init ();
        int init_size (size_t size_);
        int init_data (void *data_, size_t size_, msg_free_fn *ffn_,
            void *hint_);
        int init_delimiter ();
        int close ();
        int move (msg_t &src_);
        int copy (msg_t &src_);
        void *data ();
        size_t size ();
        unsigned char flags ();
        void set_flags (unsigned char flags_);
        void reset_flags (unsigned char flags_);
        int64_t fd ();
        void set_fd (int64_t fd_);
        metadata_t *metadata () const;
        void set_metadata (metadata_t *metadata_);
        void reset_metadata ();
        bool is_identity () const;
        bool is_credential () const;
        bool is_delimiter () const;
        bool is_vsm ();
        bool is_cmsg ();

        //  After calling this function you can copy the message in POD-style
        //  refs_ times. No need to call copy.
        void add_refs (int refs_);

        //  Removes references previously added by add_refs. If the number of
        //  references drops to 0, the message is closed and false is returned.
        bool rm_refs (int refs_);

    private:

        //  Size in bytes of the largest message that is still copied around
        //  rather than being reference-counted.
        enum { msg_t_size = 64 };
        enum { max_vsm_size = msg_t_size - (8 + sizeof (metadata_t *) + 3) };

        //  Shared message buffer. Message data are either allocated in one
        //  continuous block along with this structure - thus avoiding one
        //  malloc/free pair or they are stored in used-supplied memory.
        //  In the latter case, ffn member stores pointer to the function to be
        //  used to deallocate the data. If the buffer is actually shared (there
        //  are at least 2 references to it) refcount member contains number of
        //  references.
        struct content_t
        {
            void *data;
            size_t size;
            msg_free_fn *ffn;
            void *hint;
            zmq::atomic_counter_t refcnt;
        };

        //  Different message types.
        enum type_t
        {
            type_min = 101,
            //  VSM messages store the content in the message itself
            type_vsm = 101,
            //  LMSG messages store the content in malloc-ed memory
            type_lmsg = 102,
            //  Delimiter messages are used in envelopes
            type_delimiter = 103,
            //  CMSG messages point to constant data
            type_cmsg = 104,
            type_max = 104
        };

        // the file descriptor where this message originated, needs to be 64bit due to alignment
        int64_t file_desc;

        //  Note that fields shared between different message types are not
        //  moved to the parent class (msg_t). This way we get tighter packing
        //  of the data. Shared fields can be accessed via 'base' member of
        //  the union.
        union {
            struct {
                metadata_t *metadata;
                unsigned char unused [msg_t_size - (8 + sizeof (metadata_t *) + 2)];
                unsigned char type;
                unsigned char flags;
            } base;
            struct {
                metadata_t *metadata;
                unsigned char data [max_vsm_size];
                unsigned char size;
                unsigned char type;
                unsigned char flags;
            } vsm;
            struct {
                metadata_t *metadata;
                content_t *content;
                unsigned char unused [msg_t_size - (8 + sizeof (metadata_t *) + sizeof (content_t*) + 2)];
                unsigned char type;
                unsigned char flags;
            } lmsg;
            struct {
                metadata_t *metadata;
                void* data;
                size_t size;
                unsigned char unused
                    [msg_t_size - (8 + sizeof (metadata_t *) + sizeof (void*) + sizeof (size_t) + 2)];
                unsigned char type;
                unsigned char flags;
            } cmsg;
            struct {
                metadata_t *metadata;
                unsigned char unused [msg_t_size - (8 + sizeof (metadata_t *) + 2)];
                unsigned char type;
                unsigned char flags;
            } delimiter;
        } u;
    };

}

#endif
