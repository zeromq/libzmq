/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include <stdlib.h>

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#endif

#include "random.hpp"
#include "stdint.hpp"
#include "clock.hpp"
#include "mutex.hpp"
#include "macros.hpp"

#if defined(ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

void zmq::seed_random ()
{
#if defined ZMQ_HAVE_WINDOWS
    const int pid = static_cast<int> (GetCurrentProcessId ());
#else
    int pid = static_cast<int> (getpid ());
#endif
    srand (static_cast<unsigned int> (clock_t::now_us () + pid));
}

uint32_t zmq::generate_random ()
{
    //  Compensate for the fact that rand() returns signed integer.
    const uint32_t low = static_cast<uint32_t> (rand ());
    uint32_t high = static_cast<uint32_t> (rand ());
    high <<= (sizeof (int) * 8 - 1);
    return high | low;
}

static void manage_random (bool init_)
{
#if defined(ZMQ_USE_LIBSODIUM)
    if (init_) {
        //  sodium_init() is now documented as thread-safe in recent versions
        int rc = sodium_init ();
        zmq_assert (rc != -1);
#if defined(ZMQ_LIBSODIUM_RANDOMBYTES_CLOSE)
    } else {
        // randombytes_close either a no-op or not threadsafe
        // doing this without refcounting can cause crashes
        // if called while a context is active
        randombytes_close ();
#endif
    }
#else
    LIBZMQ_UNUSED (init_);
#endif
}

void zmq::random_open ()
{
    manage_random (true);
}

void zmq::random_close ()
{
    manage_random (false);
}
