/*
    Copyright (c) 2007-2011 iMatix Corporation
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

#include "msg.hpp"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <new>

#include "stdint.hpp"
#include "err.hpp"

int zmq_msg_init (zmq_msg_t *msg_)
{
    msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
    msg_->flags = 0;
    msg_->vsm_size = 0;
    return 0;
}

int zmq_msg_init_size (zmq_msg_t *msg_, size_t size_)
{
    if (size_ <= ZMQ_MAX_VSM_SIZE) {
        msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
        msg_->flags = 0;
        msg_->vsm_size = (uint8_t) size_;
    }
    else {
        msg_->content =
            (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t) + size_);
        if (!msg_->content) {
            errno = ENOMEM;
            return -1;
        }
        msg_->flags = 0;
        
        zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
        content->data = (void*) (content + 1);
        content->size = size_;
        content->ffn = NULL;
        content->hint = NULL;
        new (&content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq_msg_init_data (zmq_msg_t *msg_, void *data_, size_t size_,
    zmq_free_fn *ffn_, void *hint_)
{
    msg_->content = (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t));
    alloc_assert (msg_->content);
    msg_->flags = 0;
    zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
    content->data = data_;
    content->size = size_;
    content->ffn = ffn_;
    content->hint = hint_;
    new (&content->refcnt) zmq::atomic_counter_t ();
    return 0;
}

int zmq_msg_close (zmq_msg_t *msg_)
{
    //  For VSMs and delimiters there are no resources to free.
    if (msg_->content != (zmq::msg_content_t*) ZMQ_DELIMITER &&
          msg_->content != (zmq::msg_content_t*) ZMQ_VSM) {

        //  If the content is not shared, or if it is shared and the reference.
        //  count has dropped to zero, deallocate it.
        zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
        if (!(msg_->flags & ZMQ_MSG_SHARED) || !content->refcnt.sub (1)) {

            //  We used "placement new" operator to initialize the reference.
            //  counter so we call its destructor now.
            content->refcnt.~atomic_counter_t ();

            if (content->ffn)
                content->ffn (content->data, content->hint);
            free (content);
        }
    }

    //  As a safety measure, let's make the deallocated message look like
    //  an empty message.
    msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
    msg_->flags = 0;
    msg_->vsm_size = 0;

    return 0;
}

int zmq_msg_move (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    zmq_msg_close (dest_);
    *dest_ = *src_;
    zmq_msg_init (src_);
    return 0;
}

int zmq_msg_copy (zmq_msg_t *dest_, zmq_msg_t *src_)
{
    zmq_msg_close (dest_);

    //  VSMs and delimiters require no special handling.
    if (src_->content != (zmq::msg_content_t*) ZMQ_DELIMITER &&
          src_->content != (zmq::msg_content_t*) ZMQ_VSM) {

        //  One reference is added to shared messages. Non-shared messages
        //  are turned into shared messages and reference count is set to 2.
        zmq::msg_content_t *content = (zmq::msg_content_t*) src_->content;
        if (src_->flags & ZMQ_MSG_SHARED)
            content->refcnt.add (1);
        else {
            src_->flags |= ZMQ_MSG_SHARED;
            content->refcnt.set (2);
        }
    }

    *dest_ = *src_;
    return 0;
}

void *zmq_msg_data (zmq_msg_t *msg_)
{
    if (msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return msg_->vsm_data;
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER)
        return NULL;

    return ((zmq::msg_content_t*) msg_->content)->data;
}

size_t zmq_msg_size (zmq_msg_t *msg_)
{
    if (msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return msg_->vsm_size;
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER)
        return 0;

    return ((zmq::msg_content_t*) msg_->content)->size;
}
