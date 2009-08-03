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

#ifndef __ZMQ_MUTEX_HPP_INCLUDED__
#define __ZMQ_MUTEX_HPP_INCLUDED__

#include "platform.hpp"
#include "err.hpp"

//  Mutex class encapsulates OS mutex in a platform-independent way.

#ifdef ZMQ_HAVE_WINDOWS

#include "windows.hpp"

namespace zmq
{

    class mutex_t
    {
    public:
        inline mutex_t ()
        {
            InitializeCriticalSection (&cs);
        }

        inline ~mutex_t ()
        {
            DeleteCriticalSection (&cs);
        }

        inline void lock ()
        {
            EnterCriticalSection (&cs);
        }

        inline void unlock ()
        {
            LeaveCriticalSection (&cs);
        }

    private:

        CRITICAL_SECTION cs;

        //  Disable copy construction and assignment.
        mutex_t (const mutex_t&);
        void operator = (const mutex_t&);
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
            int rc = pthread_mutex_init (&mutex, NULL);
            errno_assert (rc == 0);
        }

        inline ~mutex_t ()
        {
            int rc = pthread_mutex_destroy (&mutex);
            errno_assert (rc == 0);
        }

        inline void lock ()
        {
            int rc = pthread_mutex_lock (&mutex);
            errno_assert (rc == 0);
        }

        inline void unlock ()
        {
            int rc = pthread_mutex_unlock (&mutex);
            errno_assert (rc == 0);
        }

    private:

        pthread_mutex_t mutex;

        //  Disable copy construction and assignment.
        mutex_t (const mutex_t&);
        void operator = (const mutex_t&);
    };

}

#endif

#endif
