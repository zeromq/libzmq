/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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
#include "err.hpp"
#include "fd.hpp"
#include "atomic_counter.hpp"
#include "metadata.hpp"

//  bits 2-5
#define CMD_TYPE_MASK 0x1c

//  Signature for free function to deallocate the message content.
//  Note that it has to be declared as "C" so that it is the same as
//  zmq_free_fn defined in zmq.h.
extern "C" {
typedef void(msg_free_fn) (void *data_, void *hint_);
}

namespace zmq
{
//  Note that this structure needs to be explicitly constructed
//  (init functions) and destructed (close function).

static const char cancel_cmd_name[] = "\6CANCEL";
static const char sub_cmd_name[] = "\x9SUBSCRIBE";

class msg_t
{
  public:
    //  Shared message buffer. Message data are either allocated in one
    //  continuous block along with this structure - thus avoiding one
    //  malloc/free pair or they are stored in user-supplied memory.
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

    //  Message flags.
    enum
    {
        more = 1,    //  Followed by more parts
        command = 2, //  Command frame (see ZMTP spec)
        //  Command types, use only bits 2-5 and compare with ==, not bitwise,
        //  a command can never be of more that one type at the same time
        ping = 4,
        pong = 8,
        subscribe = 12,
        cancel = 16,
        close_cmd = 20,
        credential = 32,
        routing_id = 64,
        shared = 128
    };

    bool check () const;
    int init ();

    int init (void *data_,
              size_t size_,
              msg_free_fn *ffn_,
              void *hint_,
              content_t *content_ = NULL);

    int init_size (size_t size_);
    int init_buffer (const void *buf_, size_t size_);
    int init_data (void *data_, size_t size_, msg_free_fn *ffn_, void *hint_);
    int init_external_storage (content_t *content_,
                               void *data_,
                               size_t size_,
                               msg_free_fn *ffn_,
                               void *hint_);
    int init_delimiter ();
    int init_join ();
    int init_leave ();
    int init_subscribe (const size_t size_, const unsigned char *topic);
    int init_cancel (const size_t size_, const unsigned char *topic);
    int close ();
    int move (msg_t &src_);
    int copy (msg_t &src_);
    void *data ();
    size_t size () const;
    unsigned char flags () const;
    void set_flags (unsigned char flags_);
    void reset_flags (unsigned char flags_);
    metadata_t *metadata () const;
    void set_metadata (metadata_t *metadata_);
    void reset_metadata ();
    bool is_routing_id () const;
    bool is_credential () const;
    bool is_delimiter () const;
    bool is_join () const;
    bool is_leave () const;
    bool is_ping () const;
    bool is_pong () const;
    bool is_close_cmd () const;

    //  These are called on each message received by the session_base class,
    //  so get them inlined to avoid the overhead of 2 function calls per msg
    bool is_subscribe () const
    {
        return (_u.base.flags & CMD_TYPE_MASK) == subscribe;
    }

    bool is_cancel () const
    {
        return (_u.base.flags & CMD_TYPE_MASK) == cancel;
    }

    size_t command_body_size () const;
    void *command_body ();
    bool is_vsm () const;
    bool is_cmsg () const;
    bool is_lmsg () const;
    bool is_zcmsg () const;
    uint32_t get_routing_id () const;
    int set_routing_id (uint32_t routing_id_);
    int reset_routing_id ();
    const char *group () const;
    int set_group (const char *group_);
    int set_group (const char *, size_t length_);

    //  After calling this function you can copy the message in POD-style
    //  refs_ times. No need to call copy.
    void add_refs (int refs_);

    //  Removes references previously added by add_refs. If the number of
    //  references drops to 0, the message is closed and false is returned.
    bool rm_refs (int refs_);

    void shrink (size_t new_size_);

    //  Size in bytes of the largest message that is still copied around
    //  rather than being reference-counted.
    enum
    {
        msg_t_size = 64
    };
    enum
    {
        max_vsm_size =
          msg_t_size - (sizeof (metadata_t *) + 3 + 16 + sizeof (uint32_t))
    };
    enum
    {
        ping_cmd_name_size = 5,   // 4PING
        cancel_cmd_name_size = 7, // 6CANCEL
        sub_cmd_name_size = 10    // 9SUBSCRIBE
    };

  private:
    zmq::atomic_counter_t *refcnt ();

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

        // zero-copy LMSG message for v2_decoder
        type_zclmsg = 105,

        //  Join message for radio_dish
        type_join = 106,

        //  Leave message for radio_dish
        type_leave = 107,

        type_max = 107
    };

    enum group_type_t
    {
        group_type_short,
        group_type_long
    };

    struct long_group_t
    {
        char group[ZMQ_GROUP_MAX_LENGTH + 1];
        atomic_counter_t refcnt;
    };

    union group_t
    {
        unsigned char type;
        struct
        {
            unsigned char type;
            char group[15];
        } sgroup;
        struct
        {
            unsigned char type;
            long_group_t *content;
        } lgroup;
    };

    //  Note that fields shared between different message types are not
    //  moved to the parent class (msg_t). This way we get tighter packing
    //  of the data. Shared fields can be accessed via 'base' member of
    //  the union.
    union
    {
        struct
        {
            metadata_t *metadata;
            unsigned char unused[msg_t_size
                                 - (sizeof (metadata_t *) + 2
                                    + sizeof (uint32_t) + sizeof (group_t))];
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } base;
        struct
        {
            metadata_t *metadata;
            unsigned char data[max_vsm_size];
            unsigned char size;
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } vsm;
        struct
        {
            metadata_t *metadata;
            content_t *content;
            unsigned char
              unused[msg_t_size
                     - (sizeof (metadata_t *) + sizeof (content_t *) + 2
                        + sizeof (uint32_t) + sizeof (group_t))];
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } lmsg;
        struct
        {
            metadata_t *metadata;
            content_t *content;
            unsigned char
              unused[msg_t_size
                     - (sizeof (metadata_t *) + sizeof (content_t *) + 2
                        + sizeof (uint32_t) + sizeof (group_t))];
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } zclmsg;
        struct
        {
            metadata_t *metadata;
            void *data;
            size_t size;
            unsigned char unused[msg_t_size
                                 - (sizeof (metadata_t *) + sizeof (void *)
                                    + sizeof (size_t) + 2 + sizeof (uint32_t)
                                    + sizeof (group_t))];
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } cmsg;
        struct
        {
            metadata_t *metadata;
            unsigned char unused[msg_t_size
                                 - (sizeof (metadata_t *) + 2
                                    + sizeof (uint32_t) + sizeof (group_t))];
            unsigned char type;
            unsigned char flags;
            uint32_t routing_id;
            group_t group;
        } delimiter;
    } _u;
};

inline int close_and_return (zmq::msg_t *msg_, int echo_)
{
    // Since we abort on close failure we preserve errno for success case.
    const int err = errno;
    const int rc = msg_->close ();
    errno_assert (rc == 0);
    errno = err;
    return echo_;
}

inline int close_and_return (zmq::msg_t msg_[], int count_, int echo_)
{
    for (int i = 0; i < count_; i++)
        close_and_return (&msg_[i], 0);
    return echo_;
}
}

#endif
