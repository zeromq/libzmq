/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"

#include <errno.h>
#include <stdlib.h>
#include <new>

#include "i_api.hpp"
#include "err.hpp"
#include "dispatcher.hpp"
#include "msg.hpp"

int zmq_msg_init (zmq_msg *msg_)
{
    msg_->content = (zmq_msg_content*) ZMQ_VSM;
    msg_->vsm_size = 0;
    return 0;
}

int zmq_msg_init_size (zmq_msg *msg_, size_t size_)
{
    if (size_ <= ZMQ_MAX_VSM_SIZE) {
        msg_->content = (zmq_msg_content*) ZMQ_VSM;
        msg_->vsm_size = (uint16_t) size_;
    }
    else {
        msg_->content = (zmq_msg_content*) malloc (sizeof (zmq_msg_content) +
            size_);
        if (!msg_->content) {
            errno = ENOMEM;
            return -1;
        }
        msg_->shared = 0;
            
        msg_->content->data = (void*) (msg_->content + 1);
        msg_->content->size = size_;
        msg_->content->ffn = NULL;
        new (&msg_->content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq_msg_init_data (zmq_msg *msg_, void *data_, size_t size_,
    zmq_free_fn *ffn_)
{
    msg_->shared = 0;
    msg_->content = (zmq_msg_content*) malloc (sizeof (zmq_msg_content));
    zmq_assert (msg_->content);
    msg_->content->data = data_;
    msg_->content->size = size_;
    msg_->content->ffn = ffn_;
    new (&msg_->content->refcnt) zmq::atomic_counter_t ();
    return 0;
}

int zmq_msg_close (zmq_msg *msg_)
{
    //  For VSMs and delimiters there are no resources to free
    if (msg_->content == (zmq_msg_content*) ZMQ_DELIMITER ||
          msg_->content == (zmq_msg_content*) ZMQ_VSM ||
          msg_->content == (zmq_msg_content*) ZMQ_GAP)
        return 0;

    //  If the content is not shared, or if it is shared and the reference
    //  count has dropped to zero, deallocate it.
    if (!msg_->shared || !msg_->content->refcnt.sub (1)) {

        //  We used "placement new" operator to initialize the reference
        //  counter so we call its destructor now.
        msg_->content->refcnt.~atomic_counter_t ();

        if (msg_->content->ffn)
            msg_->content->ffn (msg_->content->data);
        free (msg_->content);
    }

    return 0;
}

int zmq_msg_move (zmq_msg *dest_, zmq_msg *src_)
{
    zmq_msg_close (dest_);
    *dest_ = *src_;
    zmq_msg_init (src_);
    return 0;
}

int zmq_msg_copy (zmq_msg *dest_, zmq_msg *src_)
{
    zmq_msg_close (dest_);

    //  VSMs and delimiters require no special handling.
    if (src_->content !=
          (zmq_msg_content*) ZMQ_DELIMITER &&
          src_->content != (zmq_msg_content*) ZMQ_VSM &&
          src_->content != (zmq_msg_content*) ZMQ_GAP) {

        //  One reference is added to shared messages. Non-shared messages
        //  are turned into shared messages and reference count is set to 2.
        if (src_->shared)
            src_->content->refcnt.add (1);
        else {
            src_->shared = true;
            src_->content->refcnt.set (2);
        }
    }

    *dest_ = *src_;
    return 0;
}

void *zmq_msg_data (zmq_msg *msg_)
{
    if (msg_->content == (zmq_msg_content*) ZMQ_VSM)
        return msg_->vsm_data;
    if (msg_->content ==
          (zmq_msg_content*) ZMQ_DELIMITER ||
          msg_->content == (zmq_msg_content*) ZMQ_GAP)
        return NULL;
    return msg_->content->data;
}

size_t zmq_msg_size (zmq_msg *msg_)
{
    if (msg_->content == (zmq_msg_content*) ZMQ_VSM)
        return msg_->vsm_size;
    if (msg_->content ==
          (zmq_msg_content*) ZMQ_DELIMITER ||
          msg_->content == (zmq_msg_content*) ZMQ_GAP)
        return 0;
    return msg_->content->size;
}

int zmq_msg_type (zmq_msg *msg_)
{
    //  If it's a genuine message, return 0.
    if (msg_->content >= (zmq_msg_content*) ZMQ_VSM)
            return 0;

    //   Trick the compiler to believe that content is an integer.
    unsigned char *offset = 0;
    return (((const unsigned char*) msg_->content) - offset);
}

void *zmq_init (int app_threads_, int io_threads_)
{
    //  There should be at least a single thread managed by the dispatcher.
    if (app_threads_ < 0 || io_threads_ < 0 ||
          app_threads_ + io_threads_ == 0) {
        errno = EINVAL;
        return NULL;
    }

    zmq::dispatcher_t *dispatcher =
        new zmq::dispatcher_t (app_threads_, io_threads_);
    zmq_assert (dispatcher);
    return (void*) dispatcher;
}

int zmq_term (void *context_)
{
    ((zmq::dispatcher_t*) context_)->shutdown ();
    return 0;
}

void *zmq_socket (void *context_, int type_)
{
    return (void*) (((zmq::dispatcher_t*) context_)->create_socket (type_));
}

int zmq_close (void *s_)
{
    ((zmq::i_api*) s_)->close ();
    return 0;
}

int zmq_bind (void *s_, const char *addr_, zmq_opts *opts_)
{
    return (((zmq::i_api*) s_)->bind (addr_, opts_));
}

int zmq_connect (void *s_, const char *addr_, zmq_opts *opts_)
{
    return (((zmq::i_api*) s_)->connect (addr_, opts_));
}

int zmq_subscribe (void *s_, const char *criteria_)
{
    return (((zmq::i_api*) s_)->subscribe (criteria_));
}

int zmq_send (void *s_, zmq_msg *msg_, int flags_)
{
    return (((zmq::i_api*) s_)->send (msg_, flags_));
}

int zmq_flush (void *s_)
{
    return (((zmq::i_api*) s_)->flush ());
}

int zmq_recv (void *s_, zmq_msg *msg_, int flags_)
{
    return (((zmq::i_api*) s_)->recv (msg_, flags_));
}
