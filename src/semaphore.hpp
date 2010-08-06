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

#ifndef __ZMQ_SEMAPHORE_HPP_INCLUDED__
#define __ZMQ_SEMAPHORE_HPP_INCLUDED__

#include "platform.hpp"
#include "err.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <semaphore.h>
#endif

namespace zmq
{
    //  Simple semaphore. Only single thread may be waiting at any given time.
    //  Also, the semaphore may not be posted before the previous post
    //  was matched by corresponding wait and the waiting thread was
    //  released.

#if defined ZMQ_HAVE_WINDOWS

    //  On Windows platform simple semaphore is implemeted using event object.

    class semaphore_t
    { 
    public:

        //  Initialise the semaphore.
        inline semaphore_t ()
        {
            ev = CreateEvent (NULL, FALSE, FALSE, NULL);
            win_assert (ev != NULL);
        }

        //  Destroy the semaphore.
        inline ~semaphore_t ()
        {
            int rc = CloseHandle (ev);
            win_assert (rc != 0);    
        }

        //  Wait for the semaphore.
        inline void wait ()
        {
            DWORD rc = WaitForSingleObject (ev, INFINITE);
            win_assert (rc != WAIT_FAILED);
        }

        //  Post the semaphore.
        inline void post ()
        {
            int rc = SetEvent (ev);
            win_assert (rc != 0);
        }

    private:

        HANDLE ev;

        //  Disable copying of the object.
        semaphore_t (const semaphore_t&);
        void operator = (const semaphore_t&);
    };

#else

    //  Default implementation maps simple semaphore to POSIX semaphore.

    class semaphore_t
    { 
    public:

        //  Initialise the semaphore.
        inline semaphore_t ()
        {
             int rc = sem_init (&sem, 0, 0);
             errno_assert (rc != -1);
        }

        //  Destroy the semaphore.
        inline ~semaphore_t ()
        {
             int rc = sem_destroy (&sem);
             errno_assert (rc != -1);
        }

        //  Wait for the semaphore.
        inline void wait ()
        {
             int rc = sem_wait (&sem);
             errno_assert (rc != -1);
        }

        //  Post the semaphore.
        inline void post ()
        {
            int rc = sem_post (&sem);
            errno_assert (rc != -1);
        }

    private:

        //  Underlying system semaphore object.
        sem_t sem;

        //  Disable copying of the object.
        semaphore_t (const semaphore_t&);
        void operator = (const semaphore_t&);
    };

#endif

}

#endif

