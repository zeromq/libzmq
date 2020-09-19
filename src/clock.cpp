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
#include "clock.hpp"
#include "likely.hpp"
#include "config.hpp"
#include "err.hpp"
#include "mutex.hpp"

#include <stddef.h>

#if defined _MSC_VER
#if defined _WIN32_WCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#if defined(_M_ARM) || defined(_M_ARM64)
#include <arm_neon.h>
#endif
#endif
#endif

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/time.h>
#endif

#if defined HAVE_CLOCK_GETTIME || defined HAVE_GETHRTIME
#include <time.h>
#endif

#if defined ZMQ_HAVE_VXWORKS
#include "timers.h"
#endif

#if defined ZMQ_HAVE_OSX
int alt_clock_gettime (int clock_id, timespec *ts)
{
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service (mach_host_self (), clock_id, &cclock);
    clock_get_time (cclock, &mts);
    mach_port_deallocate (mach_task_self (), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
    return 0;
}
#endif

#ifdef ZMQ_HAVE_WINDOWS
typedef ULONGLONG (*f_compatible_get_tick_count64) ();

static zmq::mutex_t compatible_get_tick_count64_mutex;

ULONGLONG compatible_get_tick_count64 ()
{
#ifdef ZMQ_HAVE_WINDOWS_UWP
    const ULONGLONG result = ::GetTickCount64 ();
    return result;
#else
    zmq::scoped_lock_t locker (compatible_get_tick_count64_mutex);

    static DWORD s_wrap = 0;
    static DWORD s_last_tick = 0;
    const DWORD current_tick = ::GetTickCount ();

    if (current_tick < s_last_tick)
        ++s_wrap;

    s_last_tick = current_tick;
    const ULONGLONG result = (static_cast<ULONGLONG> (s_wrap) << 32)
                             + static_cast<ULONGLONG> (current_tick);

    return result;
#endif
}

f_compatible_get_tick_count64 init_compatible_get_tick_count64 ()
{
    f_compatible_get_tick_count64 func = NULL;
#if !defined ZMQ_HAVE_WINDOWS_UWP

    const HMODULE module = ::LoadLibraryA ("Kernel32.dll");
    if (module != NULL)
        func = reinterpret_cast<f_compatible_get_tick_count64> (
          ::GetProcAddress (module, "GetTickCount64"));
#endif
    if (func == NULL)
        func = compatible_get_tick_count64;

#if !defined ZMQ_HAVE_WINDOWS_UWP
    if (module != NULL)
        ::FreeLibrary (module);
#endif

    return func;
}

static f_compatible_get_tick_count64 my_get_tick_count64 =
  init_compatible_get_tick_count64 ();
#endif

const uint64_t usecs_per_msec = 1000;
const uint64_t usecs_per_sec = 1000000;
const uint64_t nsecs_per_usec = 1000;

zmq::clock_t::clock_t () :
    _last_tsc (rdtsc ()),
#ifdef ZMQ_HAVE_WINDOWS
    _last_time (static_cast<uint64_t> ((*my_get_tick_count64) ()))
#else
    _last_time (now_us () / usecs_per_msec)
#endif
{
}

uint64_t zmq::clock_t::now_us ()
{
#if defined ZMQ_HAVE_WINDOWS

    //  Get the high resolution counter's accuracy.
    //  While QueryPerformanceFrequency only needs to be called once, since its
    //  value does not change during runtime, we query it here since this is a
    //  static function. It might make sense to cache it, though.
    LARGE_INTEGER ticks_per_second;
    QueryPerformanceFrequency (&ticks_per_second);

    //  What time is it?
    LARGE_INTEGER tick;
    QueryPerformanceCounter (&tick);

    //  Convert the tick number into the number of seconds
    //  since the system was started.
    const double ticks_div =
      static_cast<double> (ticks_per_second.QuadPart) / usecs_per_sec;
    return static_cast<uint64_t> (tick.QuadPart / ticks_div);

#elif defined HAVE_CLOCK_GETTIME                                               \
  && (defined CLOCK_MONOTONIC || defined ZMQ_HAVE_VXWORKS)

    //  Use POSIX clock_gettime function to get precise monotonic time.
    struct timespec tv;

#if defined ZMQ_HAVE_OSX                                                       \
  && __MAC_OS_X_VERSION_MIN_REQUIRED < 101200 // less than macOS 10.12
    int rc = alt_clock_gettime (SYSTEM_CLOCK, &tv);
#else
    int rc = clock_gettime (CLOCK_MONOTONIC, &tv);
#endif
    // Fix case where system has clock_gettime but CLOCK_MONOTONIC is not supported.
    // This should be a configuration check, but I looked into it and writing an
    // AC_FUNC_CLOCK_MONOTONIC seems beyond my powers.
    if (rc != 0) {
#ifndef ZMQ_HAVE_VXWORKS
        //  Use POSIX gettimeofday function to get precise time.
        struct timeval tv;
        int rc = gettimeofday (&tv, NULL);
        errno_assert (rc == 0);
        return tv.tv_sec * usecs_per_sec + tv.tv_usec;
#endif
    }
    return tv.tv_sec * usecs_per_sec + tv.tv_nsec / nsecs_per_usec;

#elif defined HAVE_GETHRTIME

    return gethrtime () / nsecs_per_usec;

#else

    //  Use POSIX gettimeofday function to get precise time.
    struct timeval tv;
    int rc = gettimeofday (&tv, NULL);
    errno_assert (rc == 0);
    return tv.tv_sec * usecs_per_sec + tv.tv_usec;

#endif
}

uint64_t zmq::clock_t::now_ms ()
{
    const uint64_t tsc = rdtsc ();

    //  If TSC is not supported, get precise time and chop off the microseconds.
    if (!tsc) {
#ifdef ZMQ_HAVE_WINDOWS
        // Under Windows, now_us is not so reliable since QueryPerformanceCounter
        // does not guarantee that it will use a hardware that offers a monotonic timer.
        // So, lets use GetTickCount when GetTickCount64 is not available with an workaround
        // to its 32 bit limitation.
        return static_cast<uint64_t> ((*my_get_tick_count64) ());
#else
        return now_us () / usecs_per_msec;
#endif
    }

    //  If TSC haven't jumped back (in case of migration to a different
    //  CPU core) and if not too much time elapsed since last measurement,
    //  we can return cached time value.
    if (likely (tsc - _last_tsc <= (clock_precision / 2) && tsc >= _last_tsc))
        return _last_time;

    _last_tsc = tsc;
#ifdef ZMQ_HAVE_WINDOWS
    _last_time = static_cast<uint64_t> ((*my_get_tick_count64) ());
#else
    _last_time = now_us () / usecs_per_msec;
#endif
    return _last_time;
}

uint64_t zmq::clock_t::rdtsc ()
{
#if (defined _MSC_VER && (defined _M_IX86 || defined _M_X64))
    return __rdtsc ();
#elif defined(_MSC_VER) && defined(_M_ARM)   // NC => added for windows ARM
    return __rdpmccntr64 ();
#elif defined(_MSC_VER) && defined(_M_ARM64) // NC => added for windows ARM64
    //return __rdpmccntr64 ();
    //return __rdtscp (nullptr);
    // todo: find proper implementation for ARM64
    static uint64_t snCounter = 0;
    return ++snCounter;
#elif (defined __GNUC__ && (defined __i386__ || defined __x86_64__))
    uint32_t low, high;
    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return static_cast<uint64_t> (high) << 32 | low;
#elif (defined __SUNPRO_CC && (__SUNPRO_CC >= 0x5100)                          \
       && (defined __i386 || defined __amd64 || defined __x86_64))
    union
    {
        uint64_t u64val;
        uint32_t u32val[2];
    } tsc;
    asm("rdtsc" : "=a"(tsc.u32val[0]), "=d"(tsc.u32val[1]));
    return tsc.u64val;
#elif defined(__s390__)
    uint64_t tsc;
    asm("\tstck\t%0\n" : "=Q"(tsc) : : "cc");
    return tsc;
#else
    struct timespec ts;
#if defined ZMQ_HAVE_OSX                                                       \
  && __MAC_OS_X_VERSION_MIN_REQUIRED < 101200 // less than macOS 10.12
    alt_clock_gettime (SYSTEM_CLOCK, &ts);
#else
    clock_gettime (CLOCK_MONOTONIC, &ts);
#endif
    return static_cast<uint64_t> (ts.tv_sec) * nsecs_per_usec * usecs_per_sec
           + ts.tv_nsec;
#endif
}
