/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MSG_HPP_INCLUDE__
#define __ZMQ_MSG_HPP_INCLUDE__

#include <stddef.h>
#include <stdio.h>

#include "config.hpp"
#include "err.hpp"
#include "fd.hpp"
#include "atomic_counter.hpp"
#include "metadata.hpp"

#ifndef LIBZMQ_FORCEINLINE
#ifdef _MSC_VER
#define LIBZMQ_FORCEINLINE __forceinline
#else
#define LIBZMQ_FORCEINLINE
#endif
#endif

//  bits 2-5
#define CMD_TYPE_MASK 0x1c

//  Signature for free function to deallocate the message content.
//  Note that it has to be declared as "C" so that it is the same as
//  zmq_free_fn defined in zmq.h.
extern "C" {
typedef void (ZMQ_CDECL zmq_free_fn) (
  _Pre_maybenull_ _Post_invalid_ void *data_, _In_opt_ void *hint_);
}

namespace zmq
{
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
_Check_return_ bool
set_custom_msg_allocator (_In_ zmq_custom_msg_alloc_fn *malloc_,
                          _In_ zmq_custom_msg_free_fn *free_);
_Must_inspect_result_
  _Ret_opt_bytecap_ (cb) void *malloc (_In_ size_t cb, ZMQ_MSG_ALLOC_HINT hint);
void free (_Pre_maybenull_ _Post_invalid_ void *ptr, ZMQ_MSG_ALLOC_HINT hint);
#endif

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
        zmq_free_fn *ffn;
        void *hint;
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        ZMQ_MSG_ALLOC_HINT custom_allocation_hint;
#endif
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

    LIBZMQ_FORCEINLINE bool zmq::msg_t::check () const
    {
        return (_u.base.type >= type_min) && (_u.base.type <= type_max);
    }

    LIBZMQ_FORCEINLINE void *zmq::msg_t::datap ()
    {
#ifndef NDEBUG
        //  Check the validity of the message.
        zmq_assert (check ());
#endif

        switch (_u.base.type) {
            case type_vsm:
                return _u.vsm.data;
            case type_lmsg:
                return _u.lmsg.content->data;
            case type_cmsg:
                return _u.cmsg.data;
            case type_zclmsg:
                return _u.zclmsg.content->data;
#ifndef NDEBUG
            default:
                zmq_assert (false);
#endif
        }

        return NULL;
    }

    LIBZMQ_FORCEINLINE size_t zmq::msg_t::sizep () const
    {
#ifndef NDEBUG
        //  Check the validity of the message.
        zmq_assert (check ());
#endif

        switch (_u.base.type) {
            case type_vsm:
                return _u.vsm.size;
            case type_lmsg:
                return _u.lmsg.content->size;
            case type_zclmsg:
                return _u.zclmsg.content->size;
            case type_cmsg:
                return _u.cmsg.size;
#ifndef NDEBUG
            default:
                zmq_assert (false);
#endif
        }

        return 0;
    }

    LIBZMQ_FORCEINLINE unsigned char zmq::msg_t::flagsp () const
    {
        return _u.base.flags;
    }

    int init ();

    int init (_In_reads_bytes_ (size_) void *data_,
              size_t size_,
              _In_opt_ zmq_free_fn *ffn_,
              _In_opt_ void *hint_,
              _In_opt_ content_t *content_);

    int init_size (size_t size_);

    int init_buffer (_In_reads_bytes_ (size_) const void *buf_, size_t size_);

    int init_data (_In_opt_ void *data_,
                   _When_ (data_ == NULL, _In_range_ (0, 0)) size_t size_,
                   _In_opt_ zmq_free_fn *ffn_,
                   _In_opt_ void *hint_);

    int init_external_storage (_In_ content_t *content_,
                               _In_ void *data_,
                               size_t size_,
                               _In_opt_ zmq_free_fn *ffn_,
                               _In_opt_ void *hint_);

    int init_delimiter ();
    int init_join ();
    int init_leave ();

    int init_subscribe (_When_ (topic_ == NULL, _In_range_ (0, 0))
                          const size_t size_,
                        _In_reads_bytes_opt_ (size_)
                          const unsigned char *topic_);

    int init_cancel (_When_ (topic_ == NULL, _In_range_ (0, 0))
                       const size_t size_,
                     _In_reads_bytes_ (size_) const unsigned char *topic_);

    int close ();
    int move (msg_t &src_);
    int copy (msg_t &src_);
    void *data ();
    size_t size () const;
    unsigned char flags () const;
    void set_flags (unsigned char flags_);
    void reset_flags (unsigned char flags_);
    metadata_t *metadata () const;
    void set_metadata (_In_ metadata_t *metadata_);
    void reset_metadata ();

    bool zmq::msg_t::is_routing_id () const
    {
        return (_u.base.flags & routing_id) == routing_id;
    }

    bool zmq::msg_t::is_credential () const
    {
        return (_u.base.flags & credential) == credential;
    }

    bool zmq::msg_t::is_delimiter () const
    {
        return _u.base.type == type_delimiter;
    }

    bool is_vsm () const
    {
        return _u.base.type == type_vsm;
    }

    bool is_cmsg () const
    {
        return _u.base.type == type_cmsg;
    }

    bool is_lmsg () const
    {
        return _u.base.type == type_lmsg;
    }

    bool is_zcmsg () const
    {
        return _u.base.type == type_zclmsg;
    }

    bool is_join () const
    {
        return _u.base.type == type_join;
    }

    bool is_leave () const
    {
        return _u.base.type == type_leave;
    }

    bool is_ping () const
    {
        return (_u.base.flags & CMD_TYPE_MASK) == ping;
    }

    bool zmq::msg_t::is_pong () const
    {
        return (_u.base.flags & CMD_TYPE_MASK) == pong;
    }

    bool zmq::msg_t::is_close_cmd () const
    {
        return (_u.base.flags & CMD_TYPE_MASK) == close_cmd;
    }

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

    uint32_t zmq::msg_t::get_routing_id () const
    {
        return _u.base.routing_id;
    }

    int set_routing_id (uint32_t routing_id_);
    int reset_routing_id ();
    
    _Ret_z_ const char *zmq::msg_t::group () const
    {
        if (_u.base.group.type == group_type_long)
            return _u.base.group.lgroup.content->group;
        return _u.base.group.sgroup.group;
    }

    int set_group (_In_z_ const char *group_);
    int set_group (_In_reads_ (length_) const char *group_,
                   _Pre_satisfies_ (length_ <= ZMQ_GROUP_MAX_LENGTH)
                     size_t length_);

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

    //  Message types.

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

inline int close_and_return (_Inout_ zmq::msg_t *msg_, int echo_)
{
    // Since we abort on close failure we preserve errno for success case.
    const int err = errno;
    const int rc = msg_->close ();
    errno_assert (rc == 0);
    errno = err;
    return echo_;
}

inline int close_and_return (_Inout_updates_all_ (count_) zmq::msg_t msg_[],
                             int count_,
                             int echo_)
{
    for (int i = 0; i < count_; i++)
        close_and_return (&msg_[i], 0);
    return echo_;
}
}

#endif
