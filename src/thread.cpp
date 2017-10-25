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

#include "precompiled.hpp"
#include "macros.hpp"
#include "thread.hpp"
#include "err.hpp"

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

void zmq::thread_t::setSchedulingParameters(int priority_, int schedulingPolicy_, const std::set<int>& affinity_cpus_)
{
    // not implemented
    LIBZMQ_UNUSED (priority_);
    LIBZMQ_UNUSED (schedulingPolicy_);
    LIBZMQ_UNUSED (affinity_cpus_);
}

void zmq::thread_t::setThreadName(const char *name_)
{
    // not implemented
    LIBZMQ_UNUSED (name_);
}

#else

#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

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
        self->applySchedulingParameters();
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

void zmq::thread_t::setSchedulingParameters(int priority_, int schedulingPolicy_, const std::set<int>& affinity_cpus_)
{
    thread_priority=priority_;
    thread_sched_policy=schedulingPolicy_;
    thread_affinity_cpus=affinity_cpus_;
}

void zmq::thread_t::applySchedulingParameters()         // to be called in secondary thread context
{
#if defined _POSIX_THREAD_PRIORITY_SCHEDULING && _POSIX_THREAD_PRIORITY_SCHEDULING >= 0
    int policy = 0;
    struct sched_param param;

#if _POSIX_THREAD_PRIORITY_SCHEDULING == 0 && defined _SC_THREAD_PRIORITY_SCHEDULING
    if (sysconf(_SC_THREAD_PRIORITY_SCHEDULING) < 0) {
        return;
    }
#endif
    int rc = pthread_getschedparam(descriptor, &policy, &param);
    posix_assert (rc);

    if(thread_sched_policy != ZMQ_THREAD_SCHED_POLICY_DFLT)
    {
        policy = thread_sched_policy;
    }

    /* Quoting docs:
       "Linux allows the static priority range 1 to 99 for the SCHED_FIFO and
       SCHED_RR policies, and the priority 0 for the remaining policies."
       Other policies may use the "nice value" in place of the priority:
    */
    bool use_nice_instead_priority = (policy != SCHED_FIFO) && (policy != SCHED_RR);

    if(thread_priority != ZMQ_THREAD_PRIORITY_DFLT)
    {
        if (use_nice_instead_priority)
            param.sched_priority = 0;                   // this is the only supported priority for most scheduling policies
        else
            param.sched_priority = thread_priority;     // user should provide a value between 1 and 99
    }

#ifdef __NetBSD__
    if(policy == SCHED_OTHER) param.sched_priority = -1;
#endif

    rc = pthread_setschedparam(descriptor, policy, &param);

#if defined(__FreeBSD_kernel__) || defined (__FreeBSD__)
    // If this feature is unavailable at run-time, don't abort.
    if(rc == ENOSYS) return;
#endif

    posix_assert (rc);

    if (use_nice_instead_priority &&
            thread_priority != ZMQ_THREAD_PRIORITY_DFLT)
    {
        // assume the user wants to decrease the thread's nice value
        // i.e., increase the chance of this thread being scheduled: try setting that to
        // maximum priority.
        rc = nice(-20);

        errno_assert (rc != -1);
        // IMPORTANT: EPERM is typically returned for unprivileged processes: that's because
        //            CAP_SYS_NICE capability is required or RLIMIT_NICE resource limit should be changed to avoid EPERM!

    }

#ifdef ZMQ_HAVE_PTHREAD_SET_AFFINITY
    if (!thread_affinity_cpus.empty())
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        for (std::set<int>::const_iterator it = thread_affinity_cpus.begin(); it != thread_affinity_cpus.end(); it++)
        {
            CPU_SET( (int)(*it) , &cpuset );
        }
        rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        posix_assert (rc);
    }
#endif
#endif
}

void zmq::thread_t::setThreadName(const char *name_)
{
/* The thread name is a cosmetic string, added to ease debugging of
 * multi-threaded applications. It is not a big issue if this value
 * can not be set for any reason (such as Permission denied in some
 * cases where the application changes its EUID, etc.) The value of
 * "int rc" is retained where available, to help debuggers stepping
 * through code to see its value - but otherwise it is ignored.
 */
    if (!name_)
        return;

#if defined(ZMQ_HAVE_PTHREAD_SETNAME_1)
    int rc = pthread_setname_np(name_);
    if(rc) return;
#elif defined(ZMQ_HAVE_PTHREAD_SETNAME_2)
    int rc = pthread_setname_np(descriptor, name_);
    if(rc) return;
#elif defined(ZMQ_HAVE_PTHREAD_SETNAME_3)
    int rc = pthread_setname_np(descriptor, name_, NULL);
    if(rc) return;
#elif defined(ZMQ_HAVE_PTHREAD_SET_NAME)
    pthread_set_name_np(descriptor, name_);
#endif
}

#endif
