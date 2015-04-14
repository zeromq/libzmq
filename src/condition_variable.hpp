/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_CONDITON_VARIABLE_HPP_INCLUDED__
#define __ZMQ_CONDITON_VARIABLE_HPP_INCLUDED__

#include "platform.hpp"
#include "clock.hpp"
#include "err.hpp"
#include "mutex.hpp"

//  Condition variable class encapsulates OS mutex in a platform-independent way.

#ifdef ZMQ_HAVE_WINDOWS

#include "windows.hpp"

namespace zmq
{

    class condition_variable_t
    {
    public:
        inline condition_variable_t ()
        {
            InitializeConditionVariable (&cv);
        }

        inline ~condition_variable_t ()
        {
            
        }

        inline int wait (mutex_t* mutex_, int timeout_ )
        {
            int rc = SleepConditionVariableCS(&cv, mutex_->get_cs (), timeout_);

            if (rc != 0)
                return 0;

            rc = GetLastError();

            if (rc != ERROR_TIMEOUT)
                win_assert(rc);

            errno = EAGAIN;            
            return -1;
        }

        inline void broadcast ()
        {
            WakeAllConditionVariable(&cv);
        }

    private:

        CONDITION_VARIABLE cv;

        //  Disable copy construction and assignment.
        condition_variable_t (const condition_variable_t&);
        void operator = (const condition_variable_t&);
    };

}

#else

#include <pthread.h>

namespace zmq
{

    class condition_variable_t
    {
    public:
        inline condition_variable_t ()
        {
            int rc = pthread_cond_init (&cond, NULL);
            posix_assert (rc);
        }

        inline ~condition_variable_t ()
        {
            int rc = pthread_cond_destroy (&cond);
            posix_assert (rc);
        }

        inline int wait (mutex_t* mutex_, int timeout_)
        {
            int rc;

            if (timeout_ != -1) {
                struct timespec timeout;
                clock_gettime(CLOCK_REALTIME, &timeout);
    
                timeout.tv_sec += timeout_ / 1000;
                timeout.tv_nsec += (timeout_ % 1000) * 1000000; 
                rc = pthread_cond_timedwait (&cond, mutex_->get_mutex (), &timeout);
            }
            else
                rc = pthread_cond_wait(&cond, mutex_->get_mutex());

            if (rc == 0)
                return 0;

            if (rc == ETIMEDOUT){
                errno= EAGAIN;
                return -1;
            }

            posix_assert (rc);
            return -1;
        }

        inline void broadcast ()
        {
            int rc = pthread_cond_broadcast (&cond);
            posix_assert (rc);
        }

    private:

        pthread_cond_t cond;

        // Disable copy construction and assignment.
        condition_variable_t (const condition_variable_t&);
        const condition_variable_t &operator = (const condition_variable_t&);
    };
}

#endif


#endif
