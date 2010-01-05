/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#include "thread.hpp"
#include "err.hpp"
#include "platform.hpp"

#ifdef ZMQ_HAVE_WINDOWS

void zmq::thread_t::start (thread_fn *tfn_, void *arg_)
{
    tfn = tfn_;
    arg =arg_;
    descriptor = (HANDLE) _beginthreadex (NULL, 0,
        &zmq::thread_t::thread_routine, this, 0 , NULL);
    win_assert (descriptor != NULL);    
}

void zmq::thread_t::stop ()
{
    DWORD rc = WaitForSingleObject (descriptor, INFINITE);
    win_assert (rc != WAIT_FAILED);
}

zmq::thread_t::id_t zmq::thread_t::id ()
{
    return GetCurrentThreadId ();
}

bool zmq::thread_t::equal (id_t id1_, id_t id2_)
{
    return id1_ == id2_;
}

unsigned int __stdcall zmq::thread_t::thread_routine (void *arg_)
{
    thread_t *self = (thread_t*) arg_;
    self->tfn (self->arg);
    return 0;
}

#else

#include <signal.h>

void zmq::thread_t::start (thread_fn *tfn_, void *arg_)
{
    tfn = tfn_;
    arg =arg_;
    int rc = pthread_create (&descriptor, NULL, thread_routine, this);
    errno_assert (rc == 0);
}

void zmq::thread_t::stop ()
{
    int rc = pthread_join (descriptor, NULL);
    errno_assert (rc == 0);
}

zmq::thread_t::id_t zmq::thread_t::id ()
{
    return pthread_self ();
}

bool zmq::thread_t::equal (id_t id1_, id_t id2_)
{
    return pthread_equal (id1_, id2_) != 0;
}

void *zmq::thread_t::thread_routine (void *arg_)
{
#if !defined ZMQ_HAVE_OPENVMS
    //  Following code will guarantee more predictable latecnies as it'll
    //  disallow any signal handling in the I/O thread.
    sigset_t signal_set;
    int rc = sigfillset (&signal_set);
    errno_assert (rc == 0);
    rc = pthread_sigmask (SIG_BLOCK, &signal_set, NULL);
    errno_assert (rc == 0);
#endif

    thread_t *self = (thread_t*) arg_;   
    self->tfn (self->arg);
    return NULL;
}

#endif





