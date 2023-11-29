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
#include "atomic_counter.hpp"
#endif

void zmq::seed_random ()
{
#if !defined(_CRT_RAND_S)
#if defined ZMQ_HAVE_WINDOWS
    const int pid = static_cast<int> (GetCurrentProcessId ());
#else
    int pid = static_cast<int> (getpid ());
#endif
    srand (static_cast<unsigned int> (clock_t::now_us () + pid));
#endif
}

uint32_t zmq::generate_random ()
{
#if !defined(_CRT_RAND_S)
    //  Compensate for the fact that rand() returns signed integer.
    const uint32_t low = static_cast<uint32_t> (rand ());
    uint32_t high = static_cast<uint32_t> (rand ());
    high <<= (sizeof (int) * 8 - 1);
    return high | low;
#else
    uint32_t rnd;
    rand_s (&rnd);
    return rnd;
#endif
}

#if defined(ZMQ_USE_LIBSODIUM) && defined(ZMQ_LIBSODIUM_RANDOMBYTES_CLOSE)
static zmq::atomic_counter_t cryptolib_refcount;
#endif

static void manage_random (bool init_)
{
#if defined(ZMQ_USE_LIBSODIUM)
    if (init_) {
#if defined(ZMQ_LIBSODIUM_RANDOMBYTES_CLOSE)
        if (cryptolib_refcount.add (1) == 0) {`
#endif
            // sodium_init() is thread-safe and idempotent
            int rc = sodium_init ();
            zmq_assert (rc != -1);
#if defined(ZMQ_LIBSODIUM_RANDOMBYTES_CLOSE)
        }
    } else {
        if (cryptolib_refcount.sub (1) == false) {
            // randombytes_close either a no-op or not threadsafe
            // doing this without refcounting can cause crashes
            // if called while a context is active
            randombytes_close ();
        }
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
