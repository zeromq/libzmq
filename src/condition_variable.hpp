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

#include "clock.hpp"
#include "err.hpp"
#include "mutex.hpp"

//  Condition variable class encapsulates OS mutex in a platform-independent way.

#ifdef ZMQ_HAVE_WINDOWS

#include "windows.hpp"
#if defined(_MSC_VER)
#if _MSC_VER >= 1800
#define _SUPPORT_CONDITION_VARIABLE 1
#else
#define _SUPPORT_CONDITION_VARIABLE 0
#endif
#else
#if _cplusplus >= 201103L
#define _SUPPORT_CONDITION_VARIABLE 1
#else
#define _SUPPORT_CONDITION_VARIABLE 0
#endif
#endif

// Condition variable is supported from Windows Vista only, to use condition variable define _WIN32_WINNT to 0x0600
#if _WIN32_WINNT < 0x0600 && !_SUPPORT_CONDITION_VARIABLE

namespace zmq
{

    class condition_variable_t
    {
    public:
        inline condition_variable_t ()
        {
            zmq_assert(false);
        }

        inline ~condition_variable_t ()
        {

        }

        inline int wait (mutex_t* mutex_, int timeout_ )
        {
            zmq_assert(false);
            return -1;
        }

        inline void broadcast ()
        {
            zmq_assert(false);
        }

    private:

        //  Disable copy construction and assignment.
        condition_variable_t (const condition_variable_t&);
        void operator = (const condition_variable_t&);
    };

}

#else

#if _SUPPORT_CONDITION_VARIABLE || defined(ZMQ_HAVE_WINDOWS_TARGET_XP)
#include <condition_variable>
#include <mutex>
#endif

namespace zmq
{

#if !defined(ZMQ_HAVE_WINDOWS_TARGET_XP) && _WIN32_WINNT >= 0x0600
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
#else
	class condition_variable_t
	{
	public:
		inline condition_variable_t()
		{

		}

		inline ~condition_variable_t()
		{

		}

		inline int wait(mutex_t* mutex_, int timeout_)
		{
			std::unique_lock<std::mutex> lck(mtx);  // lock mtx
			mutex_->unlock();                       // unlock mutex_
			int res = 0;
			if(timeout_ == -1) {
				cv.wait(lck);                       // unlock mtx and wait cv.notify_all(), lock mtx after cv.notify_all()
			} else if (cv.wait_for(lck, std::chrono::milliseconds(timeout_)) == std::cv_status::timeout) {
				// time expired
				errno = EAGAIN;
				res = -1;
			}
			lck.unlock();                           // unlock mtx
			mutex_->lock();                         // lock mutex_
			return res;
		}

		inline void broadcast()
		{
			std::unique_lock<std::mutex> lck(mtx);  // lock mtx
			cv.notify_all();
		}

	private:

		std::condition_variable cv;
		std::mutex mtx;

		//  Disable copy construction and assignment.
		condition_variable_t(const condition_variable_t&);
		void operator = (const condition_variable_t&);
	};

#endif
}

#endif

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

#if defined ZMQ_HAVE_OSX && __MAC_OS_X_VERSION_MIN_REQUIRED < 101200 // less than macOS 10.12
                alt_clock_gettime(SYSTEM_CLOCK, &timeout);
#else
                clock_gettime(CLOCK_MONOTONIC, &timeout);
#endif

                timeout.tv_sec += timeout_ / 1000;
                timeout.tv_nsec += (timeout_ % 1000) * 1000000;

                if (timeout.tv_nsec > 1000000000) {
                    timeout.tv_sec++;
                    timeout.tv_nsec -= 1000000000;
                }

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
