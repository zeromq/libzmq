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

#include "msg.hpp"
#include "../include/zmq.h"

#include <string.h>
#include <stdlib.h>
#include <new>

#include "stdint.hpp"
#include "likely.hpp"
#include "metadata.hpp"
#include "err.hpp"

//  Check whether the sizes of public representation of the message (zmq_msg_t)
//  and private representation of the message (zmq::msg_t) match.

typedef char zmq_msg_size_check
    [2 * ((sizeof (zmq::msg_t) == sizeof (zmq_msg_t)) != 0) - 1];

bool zmq::msg_t::check ()
{
     return u.base.type >= type_min && u.base.type <= type_max;
}

int zmq::msg_t::init ()
{
    u.vsm.metadata = NULL;
    u.vsm.type = type_vsm;
    u.vsm.flags = 0;
    u.vsm.size = 0;
    file_desc = -1;
    return 0;
}

int zmq::msg_t::init_size (size_t size_)
{
    file_desc = -1;
    if (size_ <= max_vsm_size) {
        u.vsm.metadata = NULL;
        u.vsm.type = type_vsm;
        u.vsm.flags = 0;
        u.vsm.size = (unsigned char) size_;
    }
    else {
        u.lmsg.metadata = NULL;
        u.lmsg.type = type_lmsg;
        u.lmsg.flags = 0;
        u.lmsg.content =
            (content_t*) malloc (sizeof (content_t) + size_);
        if (unlikely (!u.lmsg.content)) {
            errno = ENOMEM;
            return -1;
        }

        u.lmsg.content->data = u.lmsg.content + 1;
        u.lmsg.content->size = size_;
        u.lmsg.content->ffn = NULL;
        u.lmsg.content->hint = NULL;
        new (&u.lmsg.content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq::msg_t::init_data (void *data_, size_t size_, msg_free_fn *ffn_,
    void *hint_)
{
    //  If data is NULL and size is not 0, a segfault
    //  would occur once the data is accessed
    zmq_assert (data_ != NULL || size_ == 0);

    file_desc = -1;

    //  Initialize constant message if there's no need to deallocate
    if (ffn_ == NULL) {
        u.cmsg.metadata = NULL;
        u.cmsg.type = type_cmsg;
        u.cmsg.flags = 0;
        u.cmsg.data = data_;
        u.cmsg.size = size_;
    }
    else {
        u.lmsg.metadata = NULL;
        u.lmsg.type = type_lmsg;
        u.lmsg.flags = 0;
        u.lmsg.content = (content_t*) malloc (sizeof (content_t));
        if (!u.lmsg.content) {
            errno = ENOMEM;
            return -1;
        }

        u.lmsg.content->data = data_;
        u.lmsg.content->size = size_;
        u.lmsg.content->ffn = ffn_;
        u.lmsg.content->hint = hint_;
        new (&u.lmsg.content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;

}

int zmq::msg_t::init_delimiter ()
{
    u.delimiter.metadata = NULL;
    u.delimiter.type = type_delimiter;
    u.delimiter.flags = 0;
    return 0;
}

int zmq::msg_t::close ()
{
    //  Check the validity of the message.
    if (unlikely (!check ())) {
        errno = EFAULT;
        return -1;
    }

    if (u.base.type == type_lmsg) {

        //  If the content is not shared, or if it is shared and the reference
        //  count has dropped to zero, deallocate it.
        if (!(u.lmsg.flags & msg_t::shared) ||
              !u.lmsg.content->refcnt.sub (1)) {

            //  We used "placement new" operator to initialize the reference
            //  counter so we call the destructor explicitly now.
            u.lmsg.content->refcnt.~atomic_counter_t ();

            if (u.lmsg.content->ffn)
                u.lmsg.content->ffn (u.lmsg.content->data,
                    u.lmsg.content->hint);
            free (u.lmsg.content);
        }
    }

    if (u.base.metadata != NULL)
        if (u.base.metadata->drop_ref ())
            delete u.base.metadata;

    //  Make the message invalid.
    u.base.type = 0;

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

    int rc = close ();
    if (unlikely (rc < 0))
        return rc;

    if (src_.u.base.type == type_lmsg) {

        //  One reference is added to shared messages. Non-shared messages
        //  are turned into shared messages and reference count is set to 2.
        if (src_.u.lmsg.flags & msg_t::shared)
            src_.u.lmsg.content->refcnt.add (1);
        else {
            src_.u.lmsg.flags |= msg_t::shared;
            src_.u.lmsg.content->refcnt.set (2);
        }
    }

    if (src_.u.base.metadata != NULL)
        src_.u.base.metadata->add_ref ();

    *this = src_;

    return 0;

}

void *zmq::msg_t::data ()
{
    //  Check the validity of the message.
    zmq_assert (check ());

    switch (u.base.type) {
    case type_vsm:
        return u.vsm.data;
    case type_lmsg:
        return u.lmsg.content->data;
    case type_cmsg:
        return u.cmsg.data;
    default:
        zmq_assert (false);
        return NULL;
    }
}

size_t zmq::msg_t::size ()
{
    //  Check the validity of the message.
    zmq_assert (check ());

    switch (u.base.type) {
    case type_vsm:
        return u.vsm.size;
    case type_lmsg:
        return u.lmsg.content->size;
    case type_cmsg:
        return u.cmsg.size;
    default:
        zmq_assert (false);
        return 0;
    }
}

unsigned char zmq::msg_t::flags ()
{
    return u.base.flags;
}

void zmq::msg_t::set_flags (unsigned char flags_)
{
    u.base.flags |= flags_;
}

void zmq::msg_t::reset_flags (unsigned char flags_)
{
    u.base.flags &= ~flags_;
}

int64_t zmq::msg_t::fd ()
{
    return file_desc;
}

void zmq::msg_t::set_fd (int64_t fd_)
{
    file_desc = fd_;
}

zmq::metadata_t *zmq::msg_t::metadata () const
{
    return u.base.metadata;
}

void zmq::msg_t::set_metadata (zmq::metadata_t *metadata_)
{
    assert (metadata_ != NULL);
    assert (u.base.metadata == NULL);
    metadata_->add_ref ();
    u.base.metadata = metadata_;
}

void zmq::msg_t::reset_metadata ()
{
    if (u.base.metadata) {
        if (u.base.metadata->drop_ref ())
            delete u.base.metadata;
        u.base.metadata = NULL;
    }
}

bool zmq::msg_t::is_identity () const
{
    return (u.base.flags & identity) == identity;
}

bool zmq::msg_t::is_credential () const
{
    return (u.base.flags & credential) == credential;
}

bool zmq::msg_t::is_delimiter () const
{
    return u.base.type == type_delimiter;
}

bool zmq::msg_t::is_vsm ()
{
    return u.base.type == type_vsm;
}

bool zmq::msg_t::is_cmsg ()
{
    return u.base.type == type_cmsg;
}

void zmq::msg_t::add_refs (int refs_)
{
    zmq_assert (refs_ >= 0);

    //  Operation not supported for messages with metadata.
    zmq_assert (u.base.metadata == NULL);

    //  No copies required.
    if (!refs_)
        return;

    //  VSMs, CMSGS and delimiters can be copied straight away. The only
    //  message type that needs special care are long messages.
    if (u.base.type == type_lmsg) {
        if (u.lmsg.flags & msg_t::shared)
            u.lmsg.content->refcnt.add (refs_);
        else {
            u.lmsg.content->refcnt.set (refs_ + 1);
            u.lmsg.flags |= msg_t::shared;
        }
    }
}

bool zmq::msg_t::rm_refs (int refs_)
{
    zmq_assert (refs_ >= 0);

    //  Operation not supported for messages with metadata.
    zmq_assert (u.base.metadata == NULL);

    //  No copies required.
    if (!refs_)
        return true;

    //  If there's only one reference close the message.
    if (u.base.type != type_lmsg || !(u.lmsg.flags & msg_t::shared)) {
        close ();
        return false;
    }

    //  The only message type that needs special care are long messages.
    if (!u.lmsg.content->refcnt.sub (refs_)) {
        //  We used "placement new" operator to initialize the reference
        //  counter so we call the destructor explicitly now.
        u.lmsg.content->refcnt.~atomic_counter_t ();

        if (u.lmsg.content->ffn)
            u.lmsg.content->ffn (u.lmsg.content->data, u.lmsg.content->hint);
        free (u.lmsg.content);

        return false;
    }

    return true;
}
