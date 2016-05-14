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

#ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
#define __ZMQ_PRECOMPILED_HPP_INCLUDED__

#include "platform.hpp"

// This must be included before any windows headers are compiled.
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
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
#include <Mstcpip.h>
#include <mswsock.h>
#include <process.h>
#include <rpc.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
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
