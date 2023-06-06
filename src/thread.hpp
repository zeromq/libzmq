/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_THREAD_HPP_INCLUDED__
#define __ZMQ_THREAD_HPP_INCLUDED__

#if defined ZMQ_HAVE_VXWORKS
#include <vxWorks.h>
#include <taskLib.h>
#elif !defined ZMQ_HAVE_WINDOWS
#include <pthread.h>
#endif
#include <set>
#include <cstring>

namespace zmq
{
typedef void (thread_fn) (void *);

//  Class encapsulating OS thread. Thread initiation/termination is done
//  using special functions rather than in constructor/destructor so that
//  thread isn't created during object construction by accident, causing
//  newly created thread to access half-initialised object. Same applies
//  to the destruction process: Thread should be terminated before object
//  destruction begins, otherwise it can access half-destructed object.

class thread_t
{
  public:
    thread_t () :
        _tfn (NULL),
        _arg (NULL),
        _started (false),
        _thread_priority (ZMQ_THREAD_PRIORITY_DFLT),
        _thread_sched_policy (ZMQ_THREAD_SCHED_POLICY_DFLT)
    {
        memset (_name, 0, sizeof (_name));
    }

#ifdef ZMQ_HAVE_VXWORKS
    ~thread_t ()
    {
        if (descriptor != NULL || descriptor > 0) {
            taskDelete (descriptor);
        }
    }
#endif

    //  Creates OS thread. 'tfn' is main thread function. It'll be passed
    //  'arg' as an argument.
    //  Name is 16 characters max including terminating NUL. Thread naming is
    //  implemented only for pthread, and windows when a debugger is attached.
    void start (thread_fn *tfn_, void *arg_, const char *name_);

    //  Returns whether the thread was started, i.e. start was called.
    bool get_started () const;

    //  Returns whether the executing thread is the thread represented by the
    //  thread object.
    bool is_current_thread () const;

    //  Waits for thread termination.
    void stop ();

    // Sets the thread scheduling parameters. Only implemented for
    // pthread. Has no effect on other platforms.
    void setSchedulingParameters (int priority_,
                                  int scheduling_policy_,
                                  const std::set<int> &affinity_cpus_);

    //  These are internal members. They should be private, however then
    //  they would not be accessible from the main C routine of the thread.
    void applySchedulingParameters ();
    void applyThreadName ();
    thread_fn *_tfn;
    void *_arg;
    char _name[16];

  private:
    bool _started;

#ifdef ZMQ_HAVE_WINDOWS
    HANDLE _descriptor;
#if defined _WIN32_WCE
    DWORD _thread_id;
#else
    unsigned int _thread_id;
#endif
#elif defined ZMQ_HAVE_VXWORKS
    int _descriptor;
    enum
    {
        DEFAULT_PRIORITY = 100,
        DEFAULT_OPTIONS = 0,
        DEFAULT_STACK_SIZE = 4000
    };
#else
    pthread_t _descriptor;
#endif

    //  Thread scheduling parameters.
    int _thread_priority;
    int _thread_sched_policy;
    std::set<int> _thread_affinity_cpus;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (thread_t)
};
}

#endif
