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
#include <winnt.h>
#endif

bool zmq::thread_t::get_started () const
{
    return _started;
}

#ifdef ZMQ_HAVE_WINDOWS

extern "C" {
#if defined _WIN32_WCE
static DWORD thread_routine (LPVOID arg_)
#else
static unsigned int __stdcall thread_routine (void *arg_)
#endif
{
    zmq::thread_t *self = static_cast<zmq::thread_t *> (arg_);
    self->applyThreadName ();
    self->_tfn (self->_arg);
    return 0;
}
}

void zmq::thread_t::start (thread_fn *tfn_, void *arg_, const char *name_)
{
    _tfn = tfn_;
    _arg = arg_;
    if (name_)
        strncpy (_name, name_, sizeof (_name) - 1);

    // set default stack size to 4MB to avoid std::map stack overflow on x64
    unsigned int stack = 0;
#if defined _WIN64
    stack = 0x400000;
#endif

#if defined _WIN32_WCE
    _descriptor = (HANDLE) CreateThread (NULL, stack, &::thread_routine, this,
                                         0, &_thread_id);
#else
    _descriptor = (HANDLE) _beginthreadex (NULL, stack, &::thread_routine, this,
                                           0, &_thread_id);
#endif
    win_assert (_descriptor != NULL);
    _started = true;
}

bool zmq::thread_t::is_current_thread () const
{
    return GetCurrentThreadId () == _thread_id;
}

void zmq::thread_t::stop ()
{
    if (_started) {
        const DWORD rc = WaitForSingleObject (_descriptor, INFINITE);
        win_assert (rc != WAIT_FAILED);
        const BOOL rc2 = CloseHandle (_descriptor);
        win_assert (rc2 != 0);
    }
}

void zmq::thread_t::setSchedulingParameters (
  int priority_, int scheduling_policy_, const std::set<int> &affinity_cpus_)
{
    // not implemented
    LIBZMQ_UNUSED (priority_);
    LIBZMQ_UNUSED (scheduling_policy_);
    LIBZMQ_UNUSED (affinity_cpus_);
}

void zmq::thread_t::
  applySchedulingParameters () // to be called in secondary thread context
{
    // not implemented
}

namespace
{
#pragma pack(push, 8)
struct thread_info_t
{
    DWORD _type;
    LPCSTR _name;
    DWORD _thread_id;
    DWORD _flags;
};
#pragma pack(pop)
}

struct MY_EXCEPTION_REGISTRATION_RECORD
{
    typedef EXCEPTION_DISPOSITION (NTAPI *HandlerFunctionType) (
      EXCEPTION_RECORD *, void *, CONTEXT *, void *);

    MY_EXCEPTION_REGISTRATION_RECORD *Next;
    HandlerFunctionType Handler;
};

static EXCEPTION_DISPOSITION NTAPI continue_execution (EXCEPTION_RECORD *rec,
                                                       void *frame,
                                                       CONTEXT *ctx,
                                                       void *disp)
{
    return ExceptionContinueExecution;
}

void zmq::thread_t::
  applyThreadName () // to be called in secondary thread context
{
    if (!_name[0] || !IsDebuggerPresent ())
        return;

    thread_info_t thread_info;
    thread_info._type = 0x1000;
    thread_info._name = _name;
    thread_info._thread_id = -1;
    thread_info._flags = 0;

    NT_TIB *tib = ((NT_TIB *) NtCurrentTeb ());

    MY_EXCEPTION_REGISTRATION_RECORD rec;
    rec.Next = (MY_EXCEPTION_REGISTRATION_RECORD *) tib->ExceptionList;
    rec.Handler = continue_execution;

    // push our handler, raise, and finally pop our handler
    tib->ExceptionList = (_EXCEPTION_REGISTRATION_RECORD *) &rec;
    const DWORD MS_VC_EXCEPTION = 0x406D1388;
    RaiseException (MS_VC_EXCEPTION, 0,
                    sizeof (thread_info) / sizeof (ULONG_PTR),
                    (ULONG_PTR *) &thread_info);
    tib->ExceptionList =
      (_EXCEPTION_REGISTRATION_RECORD
         *) (((MY_EXCEPTION_REGISTRATION_RECORD *) tib->ExceptionList)->Next);
}

#elif defined ZMQ_HAVE_VXWORKS

extern "C" {
static void *thread_routine (void *arg_)
{
    zmq::thread_t *self = (zmq::thread_t *) arg_;
    self->applySchedulingParameters ();
    self->_tfn (self->_arg);
    return NULL;
}
}

void zmq::thread_t::start (thread_fn *tfn_, void *arg_, const char *name_)
{
    LIBZMQ_UNUSED (name_);
    _tfn = tfn_;
    _arg = arg_;
    _descriptor = taskSpawn (NULL, DEFAULT_PRIORITY, DEFAULT_OPTIONS,
                             DEFAULT_STACK_SIZE, (FUNCPTR) thread_routine,
                             (int) this, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (_descriptor != NULL || _descriptor > 0)
        _started = true;
}

void zmq::thread_t::stop ()
{
    if (_started)
        while ((_descriptor != NULL || _descriptor > 0)
               && taskIdVerify (_descriptor) == 0) {
        }
}

bool zmq::thread_t::is_current_thread () const
{
    return taskIdSelf () == _descriptor;
}

void zmq::thread_t::setSchedulingParameters (
  int priority_, int schedulingPolicy_, const std::set<int> &affinity_cpus_)
{
    _thread_priority = priority_;
    _thread_sched_policy = schedulingPolicy_;
    _thread_affinity_cpus = affinity_cpus_;
}

void zmq::thread_t::
  applySchedulingParameters () // to be called in secondary thread context
{
    int priority =
      (_thread_priority >= 0 ? _thread_priority : DEFAULT_PRIORITY);
    priority = (priority < UCHAR_MAX ? priority : DEFAULT_PRIORITY);
    if (_descriptor != NULL || _descriptor > 0) {
        taskPrioritySet (_descriptor, priority);
    }
}

void zmq::thread_t::
  applyThreadName () // to be called in secondary thread context
{
    // not implemented
}

#else

#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

extern "C" {
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
    zmq::thread_t *self = (zmq::thread_t *) arg_;
    self->applySchedulingParameters ();
    self->applyThreadName ();
    self->_tfn (self->_arg);
    return NULL;
}
}

void zmq::thread_t::start (thread_fn *tfn_, void *arg_, const char *name_)
{
    _tfn = tfn_;
    _arg = arg_;
    if (name_)
        strncpy (_name, name_, sizeof (_name) - 1);
    int rc = pthread_create (&_descriptor, NULL, thread_routine, this);
    posix_assert (rc);
    _started = true;
}

void zmq::thread_t::stop ()
{
    if (_started) {
        int rc = pthread_join (_descriptor, NULL);
        posix_assert (rc);
    }
}

bool zmq::thread_t::is_current_thread () const
{
    return bool(pthread_equal (pthread_self (), _descriptor));
}

void zmq::thread_t::setSchedulingParameters (
  int priority_, int scheduling_policy_, const std::set<int> &affinity_cpus_)
{
    _thread_priority = priority_;
    _thread_sched_policy = scheduling_policy_;
    _thread_affinity_cpus = affinity_cpus_;
}

void zmq::thread_t::
  applySchedulingParameters () // to be called in secondary thread context
{
#if defined _POSIX_THREAD_PRIORITY_SCHEDULING                                  \
  && _POSIX_THREAD_PRIORITY_SCHEDULING >= 0
    int policy = 0;
    struct sched_param param;

#if _POSIX_THREAD_PRIORITY_SCHEDULING == 0                                     \
  && defined _SC_THREAD_PRIORITY_SCHEDULING
    if (sysconf (_SC_THREAD_PRIORITY_SCHEDULING) < 0) {
        return;
    }
#endif
    int rc = pthread_getschedparam (pthread_self (), &policy, &param);
    posix_assert (rc);

    if (_thread_sched_policy != ZMQ_THREAD_SCHED_POLICY_DFLT) {
        policy = _thread_sched_policy;
    }

    /* Quoting docs:
       "Linux allows the static priority range 1 to 99 for the SCHED_FIFO and
       SCHED_RR policies, and the priority 0 for the remaining policies."
       Other policies may use the "nice value" in place of the priority:
    */
    bool use_nice_instead_priority =
      (policy != SCHED_FIFO) && (policy != SCHED_RR);

    if (_thread_priority != ZMQ_THREAD_PRIORITY_DFLT) {
        if (use_nice_instead_priority)
            param.sched_priority =
              0; // this is the only supported priority for most scheduling policies
        else
            param.sched_priority =
              _thread_priority; // user should provide a value between 1 and 99
    }

#ifdef __NetBSD__
    if (policy == SCHED_OTHER)
        param.sched_priority = -1;
#endif

    rc = pthread_setschedparam (pthread_self (), policy, &param);

#if defined(__FreeBSD_kernel__) || defined(__FreeBSD__)
    // If this feature is unavailable at run-time, don't abort.
    if (rc == ENOSYS)
        return;
#endif

    posix_assert (rc);

#if !defined ZMQ_HAVE_VXWORKS
    if (use_nice_instead_priority
        && _thread_priority != ZMQ_THREAD_PRIORITY_DFLT) {
        // assume the user wants to decrease the thread's nice value
        // i.e., increase the chance of this thread being scheduled: try setting that to
        // maximum priority.
        rc = nice (-20);

        errno_assert (rc != -1);
        // IMPORTANT: EPERM is typically returned for unprivileged processes: that's because
        //            CAP_SYS_NICE capability is required or RLIMIT_NICE resource limit should be changed to avoid EPERM!
    }
#endif

#ifdef ZMQ_HAVE_PTHREAD_SET_AFFINITY
    if (!_thread_affinity_cpus.empty ()) {
        cpu_set_t cpuset;
        CPU_ZERO (&cpuset);
        for (std::set<int>::const_iterator it = _thread_affinity_cpus.begin (),
                                           end = _thread_affinity_cpus.end ();
             it != end; it++) {
            CPU_SET ((int) (*it), &cpuset);
        }
        rc =
          pthread_setaffinity_np (pthread_self (), sizeof (cpu_set_t), &cpuset);
        posix_assert (rc);
    }
#endif
#endif
}

void zmq::thread_t::
  applyThreadName () // to be called in secondary thread context
{
    /* The thread name is a cosmetic string, added to ease debugging of
 * multi-threaded applications. It is not a big issue if this value
 * can not be set for any reason (such as Permission denied in some
 * cases where the application changes its EUID, etc.) The value of
 * "int rc" is retained where available, to help debuggers stepping
 * through code to see its value - but otherwise it is ignored.
 */
    if (!_name[0])
        return;

        /* Fails with permission denied on Android 5/6 */
#if defined(ZMQ_HAVE_ANDROID)
    return;
#endif

#if defined(ZMQ_HAVE_PTHREAD_SETNAME_1)
    int rc = pthread_setname_np (_name);
    if (rc)
        return;
#elif defined(ZMQ_HAVE_PTHREAD_SETNAME_2)
    int rc = pthread_setname_np (pthread_self (), _name);
    if (rc)
        return;
#elif defined(ZMQ_HAVE_PTHREAD_SETNAME_3)
    int rc = pthread_setname_np (pthread_self (), _name, NULL);
    if (rc)
        return;
#elif defined(ZMQ_HAVE_PTHREAD_SET_NAME)
    pthread_set_name_np (pthread_self (), _name);
#endif
}

#endif
