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

#ifndef __ZMQ_MUTEX_HPP_INCLUDED__
#define __ZMQ_MUTEX_HPP_INCLUDED__

#include "err.hpp"
#include "macros.hpp"

//  Mutex class encapsulates OS mutex in a platform-independent way.

#ifdef ZMQ_HAVE_WINDOWS

#include "windows.hpp"

namespace zmq
{
class mutex_t
{
  public:
    mutex_t () { InitializeCriticalSection (&_cs); }

    ~mutex_t () { DeleteCriticalSection (&_cs); }

    void lock () { EnterCriticalSection (&_cs); }

    bool try_lock () { return (TryEnterCriticalSection (&_cs)) ? true : false; }

    void unlock () { LeaveCriticalSection (&_cs); }

    CRITICAL_SECTION *get_cs () { return &_cs; }

  private:
    CRITICAL_SECTION _cs;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (mutex_t)
};
}

#elif defined ZMQ_HAVE_VXWORKS

#include <vxWorks.h>
#include <semLib.h>

namespace zmq
{
class mutex_t
{
  public:
    inline mutex_t ()
    {
        _semId =
          semMCreate (SEM_Q_PRIORITY | SEM_INVERSION_SAFE | SEM_DELETE_SAFE);
    }

    inline ~mutex_t () { semDelete (_semId); }

    inline void lock () { semTake (_semId, WAIT_FOREVER); }

    inline bool try_lock ()
    {
        if (semTake (_semId, NO_WAIT) == OK) {
            return true;
        }
        return false;
    }

    inline void unlock () { semGive (_semId); }

  private:
    SEM_ID _semId;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (mutex_t)
};
}

#else

#include <pthread.h>

namespace zmq
{
class mutex_t
{
  public:
    inline mutex_t ()
    {
        int rc = pthread_mutexattr_init (&_attr);
        posix_assert (rc);

        rc = pthread_mutexattr_settype (&_attr, PTHREAD_MUTEX_RECURSIVE);
        posix_assert (rc);

        rc = pthread_mutex_init (&_mutex, &_attr);
        posix_assert (rc);
    }

    inline ~mutex_t ()
    {
        int rc = pthread_mutex_destroy (&_mutex);
        posix_assert (rc);

        rc = pthread_mutexattr_destroy (&_attr);
        posix_assert (rc);
    }

    inline void lock ()
    {
        int rc = pthread_mutex_lock (&_mutex);
        posix_assert (rc);
    }

    inline bool try_lock ()
    {
        int rc = pthread_mutex_trylock (&_mutex);
        if (rc == EBUSY)
            return false;

        posix_assert (rc);
        return true;
    }

    inline void unlock ()
    {
        int rc = pthread_mutex_unlock (&_mutex);
        posix_assert (rc);
    }

    inline pthread_mutex_t *get_mutex () { return &_mutex; }

  private:
    pthread_mutex_t _mutex;
    pthread_mutexattr_t _attr;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (mutex_t)
};
}

#endif


namespace zmq
{
struct scoped_lock_t
{
    scoped_lock_t (mutex_t &mutex_) : _mutex (mutex_) { _mutex.lock (); }

    ~scoped_lock_t () { _mutex.unlock (); }

  private:
    mutex_t &_mutex;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (scoped_lock_t)
};


struct scoped_optional_lock_t
{
    scoped_optional_lock_t (mutex_t *mutex_) : _mutex (mutex_)
    {
        if (_mutex != NULL)
            _mutex->lock ();
    }

    ~scoped_optional_lock_t ()
    {
        if (_mutex != NULL)
            _mutex->unlock ();
    }

  private:
    mutex_t *_mutex;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (scoped_optional_lock_t)
};
}

#endif
