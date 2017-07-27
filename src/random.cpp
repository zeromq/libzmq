/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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
#include <stdlib.h>

#if !defined ZMQ_HAVE_WINDOWS
#include <unistd.h>
#endif

#include "random.hpp"
#include "stdint.hpp"
#include "clock.hpp"
#include "mutex.hpp"
#include "macros.hpp"

#if defined (ZMQ_USE_TWEETNACL)
#include "tweetnacl.h"
#elif defined (ZMQ_USE_LIBSODIUM)
#include "sodium.h"
#endif

void zmq::seed_random ()
{
#if defined ZMQ_HAVE_WINDOWS
    int pid = (int) GetCurrentProcessId ();
#else
    int pid = (int) getpid ();
#endif
    srand ((unsigned int) (clock_t::now_us () + pid));
}

uint32_t zmq::generate_random ()
{
    //  Compensate for the fact that rand() returns signed integer.
    uint32_t low = (uint32_t) rand ();
    uint32_t high = (uint32_t) rand ();
    high <<= (sizeof (int) * 8 - 1);
    return high | low;
}

//  When different threads have their own context the file descriptor
//  variable is shared and is subject to race conditions in tweetnacl,
//  that lead to file descriptors leaks. In long-running programs with
//  ephemeral threads this is a problem as it accumulates.
//  thread-local storage cannot be used to initialise the file descriptor
//  as it is perfectly legal to share a context among many threads, each
//  of which might call curve APIs.
//  Also libsodium documentation specifically states that sodium_init
//  must not be called concurrently from multiple threads, for the
//  same reason. Inspecting the code also reveals that the close API is
//  not thread safe.
//  The context class cannot be used with static variables as the curve
//  utility APIs like zmq_curve_keypair also call into the crypto
//  library.
//  The safest solution for all use cases therefore is to have a global,
//  static lock to serialize calls into an initialiser and a finaliser,
//  using refcounts to make sure that a thread does not close the library
//  while another is still using it.
static unsigned int random_refcount = 0;
static zmq::mutex_t random_sync;

void zmq::random_open (void)
{
#if defined (ZMQ_USE_LIBSODIUM) || \
        (defined (ZMQ_USE_TWEETNACL) && !defined (ZMQ_HAVE_WINDOWS) && !defined (ZMQ_HAVE_GETRANDOM))
    scoped_lock_t locker (random_sync);

    if (random_refcount == 0) {
        int rc = sodium_init ();
        zmq_assert (rc != -1);
    }

    ++random_refcount;
#else
    LIBZMQ_UNUSED (random_refcount);
#endif
}

void zmq::random_close (void)
{
#if defined (ZMQ_USE_LIBSODIUM) || \
        (defined (ZMQ_USE_TWEETNACL) && !defined (ZMQ_HAVE_WINDOWS) && !defined (ZMQ_HAVE_GETRANDOM))
    scoped_lock_t locker (random_sync);
    --random_refcount;

    if (random_refcount == 0) {
        randombytes_close ();
    }
#endif
}

