/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
#define __ZMQ_PRECOMPILED_HPP_INCLUDED__

//  On AIX platform, poll.h has to be included first to get consistent
//  definition of pollfd structure (AIX uses 'reqevents' and 'retnevents'
//  instead of 'events' and 'revents' and defines macros to map from POSIX-y
//  names to AIX-specific names).
//  zmq.h must be included *after* poll.h for AIX to build properly.
//  precompiled.hpp includes include/zmq.h
#if defined ZMQ_POLL_BASED_ON_POLL && defined ZMQ_HAVE_AIX
#include <poll.h>
#endif

#include "platform.hpp"

#define __STDC_LIMIT_MACROS

// This must be included before any windows headers are compiled.
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#if defined ZMQ_HAVE_OPENBSD
#define ucred sockpeercred
#endif

// 0MQ definitions and exported functions
#include "../include/zmq.h"

// 0MQ DRAFT definitions and exported functions
#include "zmq_draft.h"

// TODO: expand pch implementation to non-windows builds.
#ifdef _MSC_VER

// standard C headers
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <io.h>
#include <ipexport.h>
#include <iphlpapi.h>
#include <limits.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <process.h>
#include <rpc.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// standard C++ headers
#include <algorithm>
#include <climits>
#include <cmath>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <new>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if _MSC_VER >= 1800
#include <inttypes.h>
#endif

#if _MSC_VER >= 1700
#include <atomic>
#endif

#if defined _WIN32_WCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#endif

#if defined HAVE_LIBGSSAPI_KRB5
#include "err.hpp"
#include "msg.hpp"
#include "mechanism.hpp"
#include "session_base.hpp"
#include "gssapi_server.hpp"
#include "wire.hpp"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

#include "options.hpp"

#endif // _MSC_VER

#endif //ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
