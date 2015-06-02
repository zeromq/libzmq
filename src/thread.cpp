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

#include "thread.hpp"
#include "err.hpp"
#include "platform.hpp"

#ifdef ZMQ_HAVE_WINDOWS

extern "C"
{
#if defined _WIN32_WCE
	static DWORD thread_routine (LPVOID arg_)
#else
    static unsigned int __stdcall thread_routine (void *arg_)
#endif
    {
        zmq::thread_t *self = (zmq::thread_t*) arg_;
        self->tfn (self->arg);
        return 0;
    }
}

void zmq::thread_t::start (thread_fn *tfn_, void *arg_)
{
    tfn = tfn_;
    arg = arg_;
#if defined _WIN32_WCE
    descriptor = (HANDLE) CreateThread (NULL, 0,
        &::thread_routine, this, 0 , NULL);
#else
    descriptor = (HANDLE) _beginthreadex (NULL, 0,
        &::thread_routine, this, 0 , NULL);
#endif
    win_assert (descriptor != NULL);
}

void zmq::thread_t::stop ()
{
    DWORD rc = WaitForSingleObject (descriptor, INFINITE);
    win_assert (rc != WAIT_FAILED);
    BOOL rc2 = CloseHandle (descriptor);
    win_assert (rc2 != 0);
}

void zmq::thread_t::setSchedulingParameters(int priority_, int schedulingPolicy_)
{
    // not implemented
}

#else

#include <signal.h>

extern "C"
{
    static void *thread_routine (void *arg_)
    {
#if !defined ZMQ_HAVE_OPENVMS && !defined ZMQ_HAVE_ANDROID
        //  Following code will guarantee more predictable latencies as it'll
        //  disallow any signal handling in the I/O thread.
        sigset_t signal_set;
        int rc = sigfillset (&signal_set);
        errno_assert (rc == 0);
        rc = pthread_sigmask (SIG_BLOCK, &signal_set, NULL);
        posix_assert (rc);
#endif

        zmq::thread_t *self = (zmq::thread_t*) arg_;
        self->tfn (self->arg);
        return NULL;
    }
}

void zmq::thread_t::start (thread_fn *tfn_, void *arg_)
{
    tfn = tfn_;
    arg = arg_;
    int rc = pthread_create (&descriptor, NULL, thread_routine, this);
    posix_assert (rc);
}

void zmq::thread_t::stop ()
{
    int rc = pthread_join (descriptor, NULL);
    posix_assert (rc);
}

void zmq::thread_t::setSchedulingParameters(int priority_, int schedulingPolicy_)
{
#if !defined ZMQ_HAVE_ZOS
    int policy = 0;
    struct sched_param param;

    int rc = pthread_getschedparam(descriptor, &policy, &param);
    posix_assert (rc);

    if(priority_ != -1)
    {
        param.sched_priority = priority_;
    }

    if(schedulingPolicy_ != -1)
    {
        policy = schedulingPolicy_;
    }

    rc = pthread_setschedparam(descriptor, policy, &param);
    posix_assert (rc);
#endif
}

#endif





