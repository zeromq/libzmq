/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_CLOCK_HPP_INCLUDED__
#define __ZMQ_CLOCK_HPP_INCLUDED__

#include "macros.hpp"
#include "stdint.hpp"

#if defined ZMQ_HAVE_OSX
// TODO this is not required in this file, but condition_variable.hpp includes
// clock.hpp to get these definitions
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
#ifndef HAVE_CLOCK_GETTIME
#define HAVE_CLOCK_GETTIME
#endif

#include <mach/clock.h>
#include <mach/mach.h>
#include <time.h>
#include <sys/time.h>
#endif

namespace zmq
{
class clock_t
{
  public:
    clock_t ();

    //  CPU's timestamp counter. Returns 0 if it's not available.
    static uint64_t rdtsc ();

    //  High precision timestamp.
    static uint64_t now_us ();

    //  Low precision timestamp. In tight loops generating it can be
    //  10 to 100 times faster than the high precision timestamp.
    uint64_t now_ms ();

  private:
    //  TSC timestamp of when last time measurement was made.
    uint64_t _last_tsc;

    //  Physical time corresponding to the TSC above (in milliseconds).
    uint64_t _last_time;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (clock_t)
};
}

#endif
