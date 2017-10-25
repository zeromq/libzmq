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

#ifndef __ZMQ_THREAD_HPP_INCLUDED__
#define __ZMQ_THREAD_HPP_INCLUDED__

#ifndef ZMQ_HAVE_WINDOWS
#include <pthread.h>
#endif
#include <set>

namespace zmq
{

    typedef void (thread_fn) (void*);

    //  Class encapsulating OS thread. Thread initiation/termination is done
    //  using special functions rather than in constructor/destructor so that
    //  thread isn't created during object construction by accident, causing
    //  newly created thread to access half-initialised object. Same applies
    //  to the destruction process: Thread should be terminated before object
    //  destruction begins, otherwise it can access half-destructed object.

    class thread_t
    {
    public:

        inline thread_t ()
            : tfn(NULL)
            , arg(NULL)
            , thread_priority(ZMQ_THREAD_PRIORITY_DFLT)
            , thread_sched_policy(ZMQ_THREAD_SCHED_POLICY_DFLT)
        {
        }

        //  Creates OS thread. 'tfn' is main thread function. It'll be passed
        //  'arg' as an argument.
        void start (thread_fn *tfn_, void *arg_);

        //  Waits for thread termination.
        void stop ();

        // Sets the thread scheduling parameters. Only implemented for
        // pthread. Has no effect on other platforms.
        void setSchedulingParameters(int priority_, int schedulingPolicy_, const std::set<int>& affinity_cpus_);

        // Sets the thread name, 16 characters max including terminating NUL.
        // Only implemented for pthread. Has no effect on other platforms.
        void setThreadName(const char *name_);

        //  These are internal members. They should be private, however then
        //  they would not be accessible from the main C routine of the thread.
        void applySchedulingParameters();
        thread_fn *tfn;
        void *arg;

    private:

#ifdef ZMQ_HAVE_WINDOWS
        HANDLE descriptor;
#else
        pthread_t descriptor;
#endif

        //  Thread scheduling parameters.
        int thread_priority;
        int thread_sched_policy;
        std::set<int> thread_affinity_cpus;

        thread_t (const thread_t&);
        const thread_t &operator = (const thread_t&);
    };

}

#endif
