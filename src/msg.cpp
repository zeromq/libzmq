/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "compat.hpp"
#include "macros.hpp"
#include "msg.hpp"

#include <string.h>
#include <stdlib.h>
#include <new>

#include "stdint.hpp"
#include "likely.hpp"
#include "metadata.hpp"
#include "err.hpp"

//  Check whether the sizes of public representation of the message (zmq_msg_t)
//  and private representation of the message (zmq::msg_t) match.

#if __cplusplus >= 199711L
static_assert (sizeof (zmq::msg_t) == sizeof (zmq_msg_t),
               "zmq::msg_t and zmq_msg_t sizes do not match");
#else
typedef char
  zmq_msg_size_check[2 * ((sizeof (zmq::msg_t) == sizeof (zmq_msg_t)) != 0)
                     - 1];
#endif

#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
namespace zmq
{
_Must_inspect_result_ _Ret_opt_bytecap_ (
  cb) static void * ZMQ_CDECL default_msg_alloc (_In_ size_t cb,
                                                ZMQ_MSG_ALLOC_HINT hint)
{
#ifndef NDEBUG
    if (hint < ZMQ_MSG_ALLOC_HINT_NONE || hint > ZMQ_MSG_ALLOC_HINT_MAX) {
        zmq_assert (false);
    }
#else
    LIBZMQ_UNUSED (hint);
#endif

#if defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
    return scalable_malloc (cb);
#else
    return std::malloc (cb);
#endif
}

static void ZMQ_CDECL default_msg_free (
  _Pre_maybenull_ _Post_invalid_ void *ptr, ZMQ_MSG_ALLOC_HINT hint)
{
#ifndef NDEBUG
    if (hint < ZMQ_MSG_ALLOC_HINT_NONE || hint > ZMQ_MSG_ALLOC_HINT_MAX) {
        zmq_assert (false);
    }
#else
    LIBZMQ_UNUSED (hint);
#endif

#if defined(ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR)
    scalable_free (ptr);
#else
    std::free (ptr);
#endif
}

#ifndef NDEBUG
volatile bool _messages_allocated{false};
static bool _custom_allocator_set{false};
#endif

static zmq_custom_msg_alloc_fn *_custom_malloc = default_msg_alloc;
static zmq_custom_msg_free_fn *_custom_free = default_msg_free;

_Check_return_ bool
set_custom_msg_allocator (_In_ zmq_custom_msg_alloc_fn *malloc_,
                          _In_ zmq_custom_msg_free_fn *free_)
{
#ifndef NDEBUG
    if (_custom_allocator_set || _messages_allocated) {
        //
        // Either the allocator was already set, or messages
        // were already allocated.  In either case, we cannot
        // allow the allocator to be changed.
        //

        zmq_assert (false);
    }
#endif

    if (malloc_ && free_) {
#ifndef NDEBUG
        _custom_allocator_set = true;
#endif
        _custom_malloc = malloc_;
        _custom_free = free_;
        return true;
    }

#ifndef NDEBUG
    zmq_assert (false);
#endif

    return false;
}

_Must_inspect_result_
_Ret_opt_bytecap_ (cb) void *malloc (_In_ size_t cb, ZMQ_MSG_ALLOC_HINT hint)
{
    return _custom_malloc (cb, hint);
}

void free (_Pre_maybenull_ _Post_invalid_ void *ptr, ZMQ_MSG_ALLOC_HINT hint)
{
    _custom_free (ptr, hint);
}
} // namespace zmq
#endif

int zmq::msg_t::init (_In_reads_bytes_ (size_) void *data_,
                      size_t size_,
                      _In_opt_ zmq_free_fn *ffn_,
                      _In_opt_ void *hint_,
                      _In_opt_ content_t *content_)
{
    if (size_ <= max_vsm_size) {
        const int rc = init_size (size_);

        if (rc != -1) {
            memcpy (datap (), data_, size_);
            return 0;
        }
        return -1;
    }
    if (content_) {
        return init_external_storage (content_, data_, size_, ffn_, hint_);
    }
    return init_data (data_, size_, ffn_, hint_);
}

int zmq::msg_t::init ()
{
    _u.vsm.metadata = NULL;
    _u.vsm.type = type_vsm;
    _u.vsm.flags = 0;
    _u.vsm.size = 0;
    _u.vsm.group.sgroup.group[0] = '\0';
    _u.vsm.group.type = group_type_short;
    _u.vsm.routing_id = 0;
    return 0;
}

int zmq::msg_t::init_size (size_t size_)
{
    if (size_ <= max_vsm_size) {
        _u.vsm.metadata = NULL;
        _u.vsm.type = type_vsm;
        _u.vsm.flags = 0;
        _u.vsm.size = static_cast<unsigned char> (size_);
        _u.vsm.group.sgroup.group[0] = '\0';
        _u.vsm.group.type = group_type_short;
        _u.vsm.routing_id = 0;
    } else {
        _u.lmsg.metadata = NULL;
        _u.lmsg.type = type_lmsg;
        _u.lmsg.flags = 0;
        _u.lmsg.group.sgroup.group[0] = '\0';
        _u.lmsg.group.type = group_type_short;
        _u.lmsg.routing_id = 0;
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        _u.lmsg.content = static_cast<content_t *> (zmq::malloc (
          sizeof (content_t) + size_, ZMQ_MSG_ALLOC_HINT_OUTGOING));
#ifndef NDEBUG
        _messages_allocated = true;
#endif
#else
#ifdef ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR
        _u.lmsg.content =
          static_cast<content_t *> (scalable_malloc (sizeof (content_t) + size_));
#else
        _u.lmsg.content =
          static_cast<content_t *> (std::malloc (sizeof (content_t) + size_));
#endif
#endif
        if (unlikely (!_u.lmsg.content)) {
            errno = ENOMEM;
            return -1;
        }

        _u.lmsg.content->data = _u.lmsg.content + 1;
        _u.lmsg.content->size = size_;
        _u.lmsg.content->ffn = NULL;
        _u.lmsg.content->hint = NULL;
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        _u.lmsg.content->custom_allocation_hint = ZMQ_MSG_ALLOC_HINT_OUTGOING;
#endif
        new (&_u.lmsg.content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq::msg_t::init_buffer (_In_reads_bytes_ (size_) const void *buf_,
                             size_t size_)
{
    const int rc = init_size (size_);
    if (unlikely (rc < 0)) {
        return -1;
    }
    if (size_) {
        // NULL and zero size is allowed
        assert (NULL != buf_);
        memcpy (datap (), buf_, size_);
    }
    return 0;
}

int zmq::msg_t::init_external_storage (_In_ content_t *content_,
                                       _In_ void *data_,
                                       size_t size_,
                                       _In_opt_ zmq_free_fn *ffn_,
                                       _In_opt_ void *hint_)
{
    zmq_assert (NULL != data_);
    zmq_assert (NULL != content_);

    _u.zclmsg.metadata = NULL;
    _u.zclmsg.type = type_zclmsg;
    _u.zclmsg.flags = 0;
    _u.zclmsg.group.sgroup.group[0] = '\0';
    _u.zclmsg.group.type = group_type_short;
    _u.zclmsg.routing_id = 0;

    _u.zclmsg.content = content_;
    _u.zclmsg.content->data = data_;
    _u.zclmsg.content->size = size_;
    _u.zclmsg.content->ffn = ffn_;
    _u.zclmsg.content->hint = hint_;
    new (&_u.zclmsg.content->refcnt) zmq::atomic_counter_t ();

    return 0;
}

int zmq::msg_t::init_data (_In_opt_ void *data_,
                           _When_ (data_ == NULL, _In_range_ (0, 0))
                             size_t size_,
                           _In_opt_ zmq_free_fn *ffn_,
                           _In_opt_ void *hint_)
{
    //  If data is NULL and size is not 0, a segfault
    //  would occur once the data is accessed
    zmq_assert (data_ != NULL || size_ == 0);

    //  Initialize constant message if there's no need to deallocate
    if (ffn_ == NULL) {
        _u.cmsg.metadata = NULL;
        _u.cmsg.type = type_cmsg;
        _u.cmsg.flags = 0;
        _u.cmsg.data = data_;
        _u.cmsg.size = size_;
        _u.cmsg.group.sgroup.group[0] = '\0';
        _u.cmsg.group.type = group_type_short;
        _u.cmsg.routing_id = 0;
    } else {
        _u.lmsg.metadata = NULL;
        _u.lmsg.type = type_lmsg;
        _u.lmsg.flags = 0;
        _u.lmsg.group.sgroup.group[0] = '\0';
        _u.lmsg.group.type = group_type_short;
        _u.lmsg.routing_id = 0;
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        _u.lmsg.content = static_cast<content_t *> (
          zmq::malloc (sizeof (content_t), ZMQ_MSG_ALLOC_HINT_FIXED_SIZE));
#ifndef NDEBUG
        _messages_allocated = true;
#endif
#else
#ifdef ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR
        _u.lmsg.content =
          static_cast<content_t *> (scalable_malloc (sizeof (content_t)));
#else
        _u.lmsg.content =
          static_cast<content_t *> (std::malloc (sizeof (content_t)));
#endif
#endif
        if (!_u.lmsg.content) {
            errno = ENOMEM;
            return -1;
        }

        _u.lmsg.content->data = data_;
        _u.lmsg.content->size = size_;
        _u.lmsg.content->ffn = ffn_;
        _u.lmsg.content->hint = hint_;
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        _u.lmsg.content->custom_allocation_hint = ZMQ_MSG_ALLOC_HINT_FIXED_SIZE;
#endif
        new (&_u.lmsg.content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq::msg_t::init_delimiter ()
{
    _u.delimiter.metadata = NULL;
    _u.delimiter.type = type_delimiter;
    _u.delimiter.flags = 0;
    _u.delimiter.group.sgroup.group[0] = '\0';
    _u.delimiter.group.type = group_type_short;
    _u.delimiter.routing_id = 0;
    return 0;
}

int zmq::msg_t::init_join ()
{
    _u.base.metadata = NULL;
    _u.base.type = type_join;
    _u.base.flags = 0;
    _u.base.group.sgroup.group[0] = '\0';
    _u.base.group.type = group_type_short;
    _u.base.routing_id = 0;
    return 0;
}

int zmq::msg_t::init_leave ()
{
    _u.base.metadata = NULL;
    _u.base.type = type_leave;
    _u.base.flags = 0;
    _u.base.group.sgroup.group[0] = '\0';
    _u.base.group.type = group_type_short;
    _u.base.routing_id = 0;
    return 0;
}

int zmq::msg_t::init_subscribe (_When_ (topic_ == NULL, _In_range_ (0, 0))
                                  const size_t size_,
                                _In_reads_bytes_opt_ (size_)
                                  const unsigned char *topic_)
{
    int rc = init_size (size_);
    if (rc == 0) {
        set_flags (zmq::msg_t::subscribe);

        //  We explicitly allow a NULL subscription with size zero
        if (size_) {
            assert (topic_);
            memcpy (datap (), topic_, size_);
        }
    }
    return rc;
}

int zmq::msg_t::init_cancel (_When_ (topic_ == NULL, _In_range_ (0, 0))
                               const size_t size_,
                             _In_reads_bytes_ (size_)
                               const unsigned char *topic_)
{
    int rc = init_size (size_);
    if (rc == 0) {
        set_flags (zmq::msg_t::cancel);

        //  We explicitly allow a NULL subscription with size zero
        if (size_) {
            assert (topic_);
            memcpy (datap (), topic_, size_);
        }
    }
    return rc;
}

int zmq::msg_t::close ()
{
    //  Check the validity of the message.
    if (unlikely (!check ())) {
        errno = EFAULT;
        return -1;
    }

    if (_u.base.type == type_lmsg) {
        //  If the content is not shared, or if it is shared and the reference
        //  count has dropped to zero, deallocate it.
        if (!(_u.lmsg.flags & msg_t::shared)
            || !_u.lmsg.content->refcnt.sub (1)) {
            //  We used "placement new" operator to initialize the reference
            //  counter so we call the destructor explicitly now.
            _u.lmsg.content->refcnt.~atomic_counter_t ();

            if (_u.lmsg.content->ffn)
                _u.lmsg.content->ffn (_u.lmsg.content->data,
                                      _u.lmsg.content->hint);
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
            zmq::free (_u.lmsg.content, _u.lmsg.content->custom_allocation_hint);
#else
#ifdef ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR
            scalable_free (_u.lmsg.content);
#else
            std::free (_u.lmsg.content);
#endif
#endif
        }
    }

    if (is_zcmsg ()) {
        zmq_assert (_u.zclmsg.content->ffn);

        //  If the content is not shared, or if it is shared and the reference
        //  count has dropped to zero, deallocate it.
        if (!(_u.zclmsg.flags & msg_t::shared)
            || !_u.zclmsg.content->refcnt.sub (1)) {
            //  We used "placement new" operator to initialize the reference
            //  counter so we call the destructor explicitly now.
            _u.zclmsg.content->refcnt.~atomic_counter_t ();

            _u.zclmsg.content->ffn (_u.zclmsg.content->data,
                                    _u.zclmsg.content->hint);
        }
    }

    if (_u.base.metadata != NULL) {
        if (_u.base.metadata->drop_ref ()) {
            LIBZMQ_DELETE (_u.base.metadata);
        }
        _u.base.metadata = NULL;
    }

    if (_u.base.group.type == group_type_long) {
        if (!_u.base.group.lgroup.content->refcnt.sub (1)) {
            //  We used "placement new" operator to initialize the reference
            //  counter so we call the destructor explicitly now.
            _u.base.group.lgroup.content->refcnt.~atomic_counter_t ();
            std::free (_u.base.group.lgroup.content);
        }
    }

    //  Make the message invalid.
    _u.base.type = 0;

    return 0;
}

int zmq::msg_t::move (msg_t &src_)
{
    //  Check the validity of the source.
    if (unlikely (!src_.check ())) {
        errno = EFAULT;
        return -1;
    }

    int rc = close ();
    if (unlikely (rc < 0))
        return rc;

    *this = src_;

    rc = src_.init ();
    if (unlikely (rc < 0))
        return rc;

    return 0;
}

int zmq::msg_t::copy (msg_t &src_)
{
    //  Check the validity of the source.
    if (unlikely (!src_.check ())) {
        errno = EFAULT;
        return -1;
    }

    const int rc = close ();
    if (unlikely (rc < 0))
        return rc;

    // The initial reference count, when a non-shared message is initially
    // shared (between the original and the copy we create here).
    const atomic_counter_t::integer_t initial_shared_refcnt = 2;

    if (src_.is_lmsg () || src_.is_zcmsg ()) {
        //  One reference is added to shared messages. Non-shared messages
        //  are turned into shared messages.
        if (src_.flagsp () & msg_t::shared)
            src_.refcnt ()->add (1);
        else {
            src_.set_flags (msg_t::shared);
            src_.refcnt ()->set (initial_shared_refcnt);
        }
    }

    if (src_._u.base.metadata != NULL)
        src_._u.base.metadata->add_ref ();

    if (src_._u.base.group.type == group_type_long)
        src_._u.base.group.lgroup.content->refcnt.add (1);

    *this = src_;

    return 0;
}

void *zmq::msg_t::data ()
{
    return datap ();
}

size_t zmq::msg_t::size () const
{
    return sizep ();
}

void zmq::msg_t::shrink (size_t new_size_)
{
    zmq_assert (check ());
    zmq_assert (new_size_ <= sizep ());

    switch (_u.base.type) {
        case type_vsm:
            _u.vsm.size = static_cast<unsigned char> (new_size_);
            break;
        case type_lmsg:
            _u.lmsg.content->size = new_size_;
            break;
        case type_zclmsg:
            _u.zclmsg.content->size = new_size_;
            break;
        case type_cmsg:
            _u.cmsg.size = new_size_;
            break;
        default:
            zmq_assert (false);
    }
}

unsigned char zmq::msg_t::flags () const
{
    return flagsp();
}

void zmq::msg_t::set_flags (unsigned char flags_)
{
    _u.base.flags |= flags_;
}

void zmq::msg_t::reset_flags (unsigned char flags_)
{
    _u.base.flags &= ~flags_;
}

zmq::metadata_t *zmq::msg_t::metadata () const
{
    return _u.base.metadata;
}

void zmq::msg_t::set_metadata (_In_ zmq::metadata_t *metadata_)
{
    assert (metadata_ != NULL);
    assert (_u.base.metadata == NULL);
    metadata_->add_ref ();
    _u.base.metadata = metadata_;
}

void zmq::msg_t::reset_metadata ()
{
    if (_u.base.metadata) {
        if (_u.base.metadata->drop_ref ()) {
            LIBZMQ_DELETE (_u.base.metadata);
        }
        _u.base.metadata = NULL;
    }
}

size_t zmq::msg_t::command_body_size () const
{
    if (is_ping () || is_pong ())
        return sizep () - ping_cmd_name_size;
    else if (!(flags () & msg_t::command)
             && (is_subscribe () || is_cancel ()))
        return sizep ();
    else if (is_subscribe ())
        return sizep () - sub_cmd_name_size;
    else if (is_cancel ())
        return sizep () - cancel_cmd_name_size;

    return 0;
}

void *zmq::msg_t::command_body ()
{
    unsigned char *data = NULL;

    if (is_ping () || is_pong ())
        data =
          static_cast<unsigned char *> (datap ()) + ping_cmd_name_size;
    //  With inproc, command flag is not set for sub/cancel
    else if (!(flags () & msg_t::command)
             && (is_subscribe () || is_cancel ()))
        data = static_cast<unsigned char *> (datap ());
    else if (is_subscribe ())
        data = static_cast<unsigned char *> (datap ()) + sub_cmd_name_size;
    else if (is_cancel ())
        data =
          static_cast<unsigned char *> (datap ()) + cancel_cmd_name_size;

    return data;
}

void zmq::msg_t::add_refs (int refs_)
{
    zmq_assert (refs_ >= 0);

    //  Operation not supported for messages with metadata.
    zmq_assert (_u.base.metadata == NULL);

    //  No copies required.
    if (!refs_)
        return;

    //  VSMs, CMSGS and delimiters can be copied straight away. The only
    //  message type that needs special care are long messages.
    if (_u.base.type == type_lmsg || is_zcmsg ()) {
        if (_u.base.flags & msg_t::shared)
            refcnt ()->add (refs_);
        else {
            refcnt ()->set (refs_ + 1);
            _u.base.flags |= msg_t::shared;
        }
    }
}

bool zmq::msg_t::rm_refs (int refs_)
{
    zmq_assert (refs_ >= 0);

    //  Operation not supported for messages with metadata.
    zmq_assert (_u.base.metadata == NULL);

    //  No copies required.
    if (!refs_)
        return true;

    //  If there's only one reference close the message.
    if ((_u.base.type != type_zclmsg && _u.base.type != type_lmsg)
        || !(_u.base.flags & msg_t::shared)) {
        close ();
        return false;
    }

    //  The only message type that needs special care are long and zcopy messages.
    if (_u.base.type == type_lmsg && !_u.lmsg.content->refcnt.sub (refs_)) {
        //  We used "placement new" operator to initialize the reference
        //  counter so we call the destructor explicitly now.
        _u.lmsg.content->refcnt.~atomic_counter_t ();
        if (_u.lmsg.content->ffn) {
            _u.lmsg.content->ffn (_u.lmsg.content->data, _u.lmsg.content->hint);
        }
#ifdef ZMQ_HAVE_CUSTOM_ALLOCATOR
        zmq::free (_u.lmsg.content, _u.lmsg.content->custom_allocation_hint);
#else
#ifdef ZMQ_HAVE_TBB_SCALABLE_ALLOCATOR
        scalable_free (_u.lmsg.content);
#else
        std::free (_u.lmsg.content);
#endif
#endif
        return false;
    }

    if (is_zcmsg () && !_u.zclmsg.content->refcnt.sub (refs_)) {
        // storage for rfcnt is provided externally
        if (_u.zclmsg.content->ffn) {
            _u.zclmsg.content->ffn (_u.zclmsg.content->data,
                                    _u.zclmsg.content->hint);
        }
        return false;
    }

    return true;
}

int zmq::msg_t::set_routing_id (uint32_t routing_id_)
{
    if (routing_id_) {
        _u.base.routing_id = routing_id_;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

int zmq::msg_t::reset_routing_id ()
{
    _u.base.routing_id = 0;
    return 0;
}

int zmq::msg_t::set_group (_In_z_ const char *group_)
{
    size_t length = strnlen (group_, ZMQ_GROUP_MAX_LENGTH);

    return set_group (group_, length);
}

int zmq::msg_t::set_group (_In_reads_ (length_) const char *group_,
                           _Pre_satisfies_ (length_ <= ZMQ_GROUP_MAX_LENGTH)
                             size_t length_)
{
    if (length_ > ZMQ_GROUP_MAX_LENGTH) {
        errno = EINVAL;
        return -1;
    }

    if (length_ > 14) {
        _u.base.group.lgroup.type = group_type_long;
        _u.base.group.lgroup.content =
          (long_group_t *) std::malloc (sizeof (long_group_t));
        assert (_u.base.group.lgroup.content);
        new (&_u.base.group.lgroup.content->refcnt) zmq::atomic_counter_t ();
        _u.base.group.lgroup.content->refcnt.set (1);
        strncpy (_u.base.group.lgroup.content->group, group_, length_);
        _u.base.group.lgroup.content->group[length_] = '\0';
    } else {
        strncpy (_u.base.group.sgroup.group, group_, length_);
        _u.base.group.sgroup.group[length_] = '\0';
    }

    return 0;
}

zmq::atomic_counter_t *zmq::msg_t::refcnt ()
{
    switch (_u.base.type) {
        case type_lmsg:
            return &_u.lmsg.content->refcnt;
        case type_zclmsg:
            return &_u.zclmsg.content->refcnt;
        default:
            zmq_assert (false);
            return NULL;
    }
}
