/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_FD_HPP_INCLUDED__
#define __ZMQ_FD_HPP_INCLUDED__

#if defined _WIN32
#include "windows.hpp"
#endif

namespace zmq
{
typedef zmq_fd_t fd_t;

#ifdef ZMQ_HAVE_WINDOWS
#if defined _MSC_VER && _MSC_VER <= 1400
enum
{
    retired_fd = (fd_t) (~0)
};
#else
enum
#if _MSC_VER >= 1800
  : fd_t
#endif
{
    retired_fd = INVALID_SOCKET
};
#endif
#else
enum
{
    retired_fd = -1
};
#endif
}
#endif
