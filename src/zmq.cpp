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

#include "../bindings/c/zmq.h"

#include <errno.h>
#include <stdlib.h>
#include <new>

#include "socket_base.hpp"
#include "err.hpp"
#include "dispatcher.hpp"
#include "msg_content.hpp"
#include "platform.hpp"
#include "stdint.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#include <sys/time.h>
#endif

int zmq_msg_init (zmq_msg_t *msg_)
{
    msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
    msg_->vsm_size = 0;
    return 0;
}

int zmq_msg_init_size (zmq_msg_t *msg_, size_t size_)
{
    if (size_ <= ZMQ_MAX_VSM_SIZE) {
        msg_->content = (zmq::msg_content_t*) ZMQ_VSM;
        msg_->vsm_size = (uint8_t) size_;
    }
    else {
        msg_->content =
            (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t) + size_);
        if (!msg_->content) {
            errno = ENOMEM;
            return -1;
        }
        msg_->shared = 0;

        zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
        content->data = (void*) (content + 1);
        content->size = size_;
        content->ffn = NULL;
        new (&content->refcnt) zmq::atomic_counter_t ();
    }
    return 0;
}

int zmq_msg_init_data (zmq_msg_t *msg_, void *data_, size_t size_,
    zmq_free_fn *ffn_)
{
    msg_->shared = 0;
    msg_->content = (zmq::msg_content_t*) malloc (sizeof (zmq::msg_content_t));
    zmq_assert (msg_->content);
    zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
    content->data = data_;
    content->size = size_;
    content->ffn = ffn_;
    new (&content->refcnt) zmq::atomic_counter_t ();
    return 0;
}

int zmq_msg_close (zmq_msg_t *msg_)
{
    //  For VSMs and delimiters there are no resources to free.
    if (msg_->content == (zmq::msg_content_t*) ZMQ_DELIMITER ||
          msg_->content == (zmq::msg_content_t*) ZMQ_VSM)
        return 0;

    //  If the content is not shared, or if it is shared and the reference.
    //  count has dropped to zero, deallocate it.
    zmq::msg_content_t *content = (zmq::msg_content_t*) msg_->content;
    if (!msg_->shared || !content->refcnt.sub (1)) {

        //  We used "placement new" operator to initialize the reference.
        //  counter so we call its destructor now.
        content->refcnt.~atomic_counter_t ();

        if (content->ffn)
            content->ffn (content->data);
        free (content);
    }

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
        if (src_->shared)
            content->refcnt.add (1);
        else {
            src_->shared = true;
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

void *zmq_init (int app_threads_, int io_threads_, int flags_)
{
    //  There should be at least a single thread managed by the dispatcher.
    if (app_threads_ <= 0 || io_threads_ <= 0 ||
          app_threads_ > 63 || io_threads_ > 63) {
        errno = EINVAL;
        return NULL;
    }

    zmq::dispatcher_t *dispatcher = new zmq::dispatcher_t (app_threads_,
        io_threads_, flags_);
    zmq_assert (dispatcher);
    return (void*) dispatcher;
}

int zmq_term (void *dispatcher_)
{
    return ((zmq::dispatcher_t*) dispatcher_)->term ();
}

void *zmq_socket (void *dispatcher_, int type_)
{
    return (void*) (((zmq::dispatcher_t*) dispatcher_)->create_socket (type_));
}

int zmq_close (void *s_)
{
    ((zmq::socket_base_t*) s_)->close ();
    return 0;
}

int zmq_setsockopt (void *s_, int option_, const void *optval_,
    size_t optvallen_)
{
    return (((zmq::socket_base_t*) s_)->setsockopt (option_, optval_,
        optvallen_));
}

int zmq_bind (void *s_, const char *addr_)
{
    return (((zmq::socket_base_t*) s_)->bind (addr_));
}

int zmq_connect (void *s_, const char *addr_)
{
    return (((zmq::socket_base_t*) s_)->connect (addr_));
}

int zmq_send (void *s_, zmq_msg_t *msg_, int flags_)
{
    return (((zmq::socket_base_t*) s_)->send (msg_, flags_));
}

int zmq_flush (void *s_)
{
    return (((zmq::socket_base_t*) s_)->flush ());
}

int zmq_recv (void *s_, zmq_msg_t *msg_, int flags_)
{
    return (((zmq::socket_base_t*) s_)->recv (msg_, flags_));
}

#if defined ZMQ_HAVE_WINDOWS

static uint64_t now ()
{    
    //  Get the high resolution counter's accuracy.
    LARGE_INTEGER ticksPerSecond;
    QueryPerformanceFrequency (&ticksPerSecond);

    //  What time is it?
    LARGE_INTEGER tick;
    QueryPerformanceCounter (&tick);

    //  Convert the tick number into the number of seconds
    //  since the system was started.
    double ticks_div = (double) (ticksPerSecond.QuadPart / 1000000);     
    return (uint64_t) (tick.QuadPart / ticks_div);
}

void zmq_sleep (int seconds_)
{
    Sleep (seconds_ * 1000);
}

#else

static uint64_t now ()
{
    struct timeval tv;
    int rc;

    rc = gettimeofday (&tv, NULL);
    assert (rc == 0);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

void zmq_sleep (int seconds_)
{
    sleep (seconds_);
}

#endif

void *zmq_stopwatch_start ()
{
    uint64_t *watch = (uint64_t*) malloc (sizeof (uint64_t));
    zmq_assert (watch);
    *watch = now ();
    return (void*) watch;
}

unsigned long zmq_stopwatch_stop (void *watch_)
{
    uint64_t end = now ();
    uint64_t start = *(uint64_t*) watch_;
    free (watch_);
    return (unsigned long) (end - start);
}

