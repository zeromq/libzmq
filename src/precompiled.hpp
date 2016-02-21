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

#ifdef _MSC_VER

// Windows headers
#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#define WIN32_LEAN_AND_MEAN		// speeds up compilation by removing rarely used windows definitions from headers
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#if defined ZMQ_HAVE_OPENBSD
#define ucred sockpeercred
#endif
#endif


// system headers
#include <intrin.h>
#include <io.h>
#include <rpc.h>
#include <sys/stat.h>
#include <assert.h>
#if defined _MSC_VER
#if defined _WIN32_WCE
#include <cmnintrin.h>
#else
#include <intrin.h>
#endif
#endif
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_LIBGSSAPI_KRB5
#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "gssapi_server.hpp"
#include "wire.hpp"

#include <gssapi/gssapi.h>
#endif
#ifdef HAVE_LIBGSSAPI_KRB5

#if !defined(ZMQ_HAVE_FREEBSD) && !defined(ZMQ_HAVE_DRAGONFLY)
#include <gssapi/gssapi_generic.h>
#endif
#include <gssapi/gssapi_krb5.h>

#include "mechanism.hpp"
#include "options.hpp"
#include <gssapi/gssapi_krb5.h>
#endif
#if ((defined ZMQ_HAVE_LINUX || defined ZMQ_HAVE_FREEBSD ||\
    defined ZMQ_HAVE_OSX || defined ZMQ_HAVE_OPENBSD ||\
    defined ZMQ_HAVE_QNXNTO || defined ZMQ_HAVE_NETBSD ||\
    defined ZMQ_HAVE_DRAGONFLY || defined ZMQ_HAVE_GNU)\
    && defined ZMQ_HAVE_IFADDRS)
#include <ifaddrs.h>
#endif
#include <intrin.h>
#include <inttypes.h>
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
#include <atomic>
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


// 0MQ definitions and exported functions
#include "../include/zmq.h"

#endif // _MSC_VER

#endif //ifndef __ZMQ_PRECOMPILED_HPP_INCLUDED__
