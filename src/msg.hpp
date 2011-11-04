/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_MSG_HPP_INCLUDE__
#define __ZMQ_MSG_HPP_INCLUDE__

#include <stddef.h>

#include "config.hpp"
#include "atomic_counter.hpp"

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

        //  Mesage flags.
        enum
        {
            more = 1,
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
        bool is_delimiter ();
        bool is_vsm ();

        //  After calling this function you can copy the message in POD-style
        //  refs_ times. No need to call copy.
        void add_refs (int refs_);

        //  Removes references previously added by add_refs. If the number of
        //  references drops to 0, the message is closed and false is returned.
        bool rm_refs (int refs_);

    private:

        //  Size in bytes of the largest message that is still copied around
        //  rather than being reference-counted.
        enum {max_vsm_size = 29};

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
            type_vsm = 101,
            type_lmsg = 102,
            type_delimiter = 103,
            type_max = 103
        };

        //  Note that fields shared between different message types are not
        //  moved to tha parent class (msg_t). This way we ger tighter packing
        //  of the data. Shared fields can be accessed via 'base' member of
        //  the union.
        union {
            struct {
                unsigned char unused [max_vsm_size + 1];
                unsigned char type;
                unsigned char flags;
            } base;
            struct {
                unsigned char data [max_vsm_size];
                unsigned char size;
                unsigned char type;
                unsigned char flags;
            } vsm;
            struct {
                content_t *content;
                unsigned char unused [max_vsm_size + 1 - sizeof (content_t*)];
                unsigned char type;
                unsigned char flags;
            } lmsg;
            struct {
                unsigned char unused [max_vsm_size + 1];
                unsigned char type;
                unsigned char flags;
            } delimiter;
        } u;
    };

}

#endif
