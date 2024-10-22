/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "polling_util.hpp"

#if defined ZMQ_POLL_BASED_ON_POLL
#include <limits.h>
#include <algorithm>

zmq::timeout_t zmq::compute_timeout (const bool first_pass_,
                                     const long timeout_,
                                     const uint64_t now_,
                                     const uint64_t end_)
{
    if (first_pass_)
        return 0;

    if (timeout_ < 0)
        return -1;

    return static_cast<zmq::timeout_t> (
      std::min<uint64_t> (end_ - now_, INT_MAX));
}
#endif
