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

#ifndef __ZMQ_CONDITON_VARIABLE_HPP_INCLUDED__
#define __ZMQ_CONDITON_VARIABLE_HPP_INCLUDED__

#include "err.hpp"
#include "mutex.hpp"

//  Condition variable class encapsulates OS mutex in a platform-independent way.

#if defined(ZMQ_USE_CV_IMPL_NONE)

namespace zmq
{
class condition_variable_t
{
  public:
    inline condition_variable_t () { zmq_assert (false); }

    inline int wait (mutex_t *mutex_, int timeout_)
    {
        zmq_assert (false);
        return -1;
    }

    inline void broadcast () { zmq_assert (false); }

    ZMQ_NON_COPYABLE_NOR_MOVABLE (condition_variable_t)
};
}

#elif defined(ZMQ_USE_CV_IMPL_WIN32API)

#include "windows.hpp"

namespace zmq
{
class condition_variable_t
{
  public:
    inline condition_variable_t () { InitializeConditionVariable (&_cv); }

    inline int wait (mutex_t *mutex_, int timeout_)
    {
        int rc = SleepConditionVariableCS (&_cv, mutex_->get_cs (), timeout_);

        if (rc != 0)
            return 0;

        rc = GetLastError ();

        if (rc != ERROR_TIMEOUT)
            win_assert (rc);

        errno = EAGAIN;
        return -1;
    }

    inline void broadcast () { WakeAllConditionVariable (&_cv); }

  private:
    CONDITION_VARIABLE _cv;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (condition_variable_t)
};
}

#elif defined(ZMQ_USE_CV_IMPL_STL11)

#include <condition_variable>

namespace zmq
{
class condition_variable_t
{
  public:
    condition_variable_t () ZMQ_DEFAULT;

    int wait (mutex_t *mutex_, int timeout_)
    {
        // this assumes that the mutex mutex_ has been locked by the caller
        int res = 0;
        if (timeout_ == -1) {
            _cv.wait (
              *mutex_); // unlock mtx and wait cv.notify_all(), lock mtx after cv.notify_all()
        } else if (_cv.wait_for (*mutex_, std::chrono::milliseconds (timeout_))
                   == std::cv_status::timeout) {
            // time expired
            errno = EAGAIN;
            res = -1;
        }
        return res;
    }

    void broadcast ()
    {
        // this assumes that the mutex associated with _cv has been locked by the caller
        _cv.notify_all ();
    }

  private:
    std::condition_variable_any _cv;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (condition_variable_t)
};
}

#elif defined(ZMQ_USE_CV_IMPL_VXWORKS)

#include <sysLib.h>

namespace zmq
{
class condition_variable_t
{
  public:
    inline condition_variable_t () ZMQ_DEFAULT;

    inline ~condition_variable_t ()
    {
        scoped_lock_t l (_listenersMutex);
        for (size_t i = 0; i < _listeners.size (); i++) {
            semDelete (_listeners[i]);
        }
    }

    inline int wait (mutex_t *mutex_, int timeout_)
    {
        //Atomically releases lock, blocks the current executing thread,
        //and adds it to the list of threads waiting on *this. The thread
        //will be unblocked when broadcast() is executed.
        //It may also be unblocked spuriously. When unblocked, regardless
        //of the reason, lock is reacquired and wait exits.

        SEM_ID sem = semBCreate (SEM_Q_PRIORITY, SEM_EMPTY);
        {
            scoped_lock_t l (_listenersMutex);
            _listeners.push_back (sem);
        }
        mutex_->unlock ();

        int rc;
        if (timeout_ < 0)
            rc = semTake (sem, WAIT_FOREVER);
        else {
            int ticksPerSec = sysClkRateGet ();
            int timeoutTicks = (timeout_ * ticksPerSec) / 1000 + 1;
            rc = semTake (sem, timeoutTicks);
        }

        {
            scoped_lock_t l (_listenersMutex);
            // remove sem from listeners
            for (size_t i = 0; i < _listeners.size (); i++) {
                if (_listeners[i] == sem) {
                    _listeners.erase (_listeners.begin () + i);
                    break;
                }
            }
            semDelete (sem);
        }
        mutex_->lock ();

        if (rc == 0)
            return 0;

        if (rc == S_objLib_OBJ_TIMEOUT) {
            errno = EAGAIN;
            return -1;
        }

        return -1;
    }

    inline void broadcast ()
    {
        scoped_lock_t l (_listenersMutex);
        for (size_t i = 0; i < _listeners.size (); i++) {
            semGive (_listeners[i]);
        }
    }

  private:
    mutex_t _listenersMutex;
    std::vector<SEM_ID> _listeners;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (condition_variable_t)
};
}

#elif defined(ZMQ_USE_CV_IMPL_PTHREADS)

#include <pthread.h>

#if defined(__ANDROID_API__) && __ANDROID_API__ < 21
#define ANDROID_LEGACY
extern "C" int pthread_cond_timedwait_monotonic_np (pthread_cond_t *,
                                                    pthread_mutex_t *,
                                                    const struct timespec *);
#endif

namespace zmq
{
class condition_variable_t
{
  public:
    inline condition_variable_t ()
    {
        pthread_condattr_t attr;
        pthread_condattr_init (&attr);
#if !defined(ZMQ_HAVE_OSX) && !defined(ANDROID_LEGACY)
        pthread_condattr_setclock (&attr, CLOCK_MONOTONIC);
#endif
        int rc = pthread_cond_init (&_cond, &attr);
        posix_assert (rc);
    }

    inline ~condition_variable_t ()
    {
        int rc = pthread_cond_destroy (&_cond);
        posix_assert (rc);
    }

    inline int wait (mutex_t *mutex_, int timeout_)
    {
        int rc;

        if (timeout_ != -1) {
            struct timespec timeout;

#ifdef ZMQ_HAVE_OSX
            timeout.tv_sec = 0;
            timeout.tv_nsec = 0;
#else
            rc = clock_gettime (CLOCK_MONOTONIC, &timeout);
            posix_assert (rc);
#endif

            timeout.tv_sec += timeout_ / 1000;
            timeout.tv_nsec += (timeout_ % 1000) * 1000000;

            if (timeout.tv_nsec >= 1000000000) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000;
            }
#ifdef ZMQ_HAVE_OSX
            rc = pthread_cond_timedwait_relative_np (
              &_cond, mutex_->get_mutex (), &timeout);
#elif defined(ANDROID_LEGACY)
            rc = pthread_cond_timedwait_monotonic_np (
              &_cond, mutex_->get_mutex (), &timeout);
#else
            rc =
              pthread_cond_timedwait (&_cond, mutex_->get_mutex (), &timeout);
#endif
        } else
            rc = pthread_cond_wait (&_cond, mutex_->get_mutex ());

        if (rc == 0)
            return 0;

        if (rc == ETIMEDOUT) {
            errno = EAGAIN;
            return -1;
        }

        posix_assert (rc);
        return -1;
    }

    inline void broadcast ()
    {
        int rc = pthread_cond_broadcast (&_cond);
        posix_assert (rc);
    }

  private:
    pthread_cond_t _cond;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (condition_variable_t)
};
}

#endif

#endif
