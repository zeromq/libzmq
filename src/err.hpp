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

#ifndef __ZMQ_ERR_HPP_INCLUDED__
#define __ZMQ_ERR_HPP_INCLUDED__

#include <assert.h>
#if defined _WIN32_WCE
#include "..\builds\msvc\errno.hpp"
#else
#include <errno.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef ZMQ_HAVE_WINDOWS
#include <netdb.h>
#endif

#include "likely.hpp"

//  0MQ-specific error codes are defined in zmq.h

// EPROTO is not used by OpenBSD and maybe other platforms.
#ifndef EPROTO
#define EPROTO 0
#endif

namespace zmq
{
const char *errno_to_string (int errno_);
#if defined __clang__
#if __has_feature(attribute_analyzer_noreturn)
void zmq_abort (const char *errmsg_) __attribute__ ((analyzer_noreturn));
#else
void zmq_abort (const char *errmsg_);
#endif
#elif defined __MSCVER__
__declspec(noreturn) void zmq_abort (const char *errmsg_);
#else
void zmq_abort (const char *errmsg_);
#endif
void print_backtrace ();
}

#ifdef ZMQ_HAVE_WINDOWS

namespace zmq
{
const char *wsa_error ();
const char *
wsa_error_no (int no_,
              const char *wsae_wouldblock_string_ = "Operation would block");
void win_error (char *buffer_, size_t buffer_size_);
int wsa_error_to_errno (int errcode_);
}

//  Provides convenient way to check WSA-style errors on Windows.
#define wsa_assert(x)                                                          \
    do {                                                                       \
        if (unlikely (!(x))) {                                                 \
            const char *errstr = zmq::wsa_error ();                            \
            if (errstr != NULL) {                                              \
                fprintf (stderr, "Assertion failed: %s [%i] (%s:%d)\n",        \
                         errstr, WSAGetLastError (), __FILE__, __LINE__);      \
                fflush (stderr);                                               \
                zmq::zmq_abort (errstr);                                       \
            }                                                                  \
        }                                                                      \
    } while (false)

//  Provides convenient way to assert on WSA-style errors on Windows.
#define wsa_assert_no(no)                                                      \
    do {                                                                       \
        const char *errstr = zmq::wsa_error_no (no);                           \
        if (errstr != NULL) {                                                  \
            fprintf (stderr, "Assertion failed: %s (%s:%d)\n", errstr,         \
                     __FILE__, __LINE__);                                      \
            fflush (stderr);                                                   \
            zmq::zmq_abort (errstr);                                           \
        }                                                                      \
    } while (false)

// Provides convenient way to check GetLastError-style errors on Windows.
#define win_assert(x)                                                          \
    do {                                                                       \
        if (unlikely (!(x))) {                                                 \
            char errstr[256];                                                  \
            zmq::win_error (errstr, 256);                                      \
            fprintf (stderr, "Assertion failed: %s (%s:%d)\n", errstr,         \
                     __FILE__, __LINE__);                                      \
            fflush (stderr);                                                   \
            zmq::zmq_abort (errstr);                                           \
        }                                                                      \
    } while (false)

#endif

//  This macro works in exactly the same way as the normal assert. It is used
//  in its stead because standard assert on Win32 in broken - it prints nothing
//  when used within the scope of JNI library.
#define zmq_assert(x)                                                          \
    do {                                                                       \
        if (unlikely (!(x))) {                                                 \
            fprintf (stderr, "Assertion failed: %s (%s:%d)\n", #x, __FILE__,   \
                     __LINE__);                                                \
            fflush (stderr);                                                   \
            zmq::zmq_abort (#x);                                               \
        }                                                                      \
    } while (false)

//  Provides convenient way to check for errno-style errors.
#define errno_assert(x)                                                        \
    do {                                                                       \
        if (unlikely (!(x))) {                                                 \
            const char *errstr = strerror (errno);                             \
            fprintf (stderr, "%s (%s:%d)\n", errstr, __FILE__, __LINE__);      \
            fflush (stderr);                                                   \
            zmq::zmq_abort (errstr);                                           \
        }                                                                      \
    } while (false)

//  Provides convenient way to check for POSIX errors.
#define posix_assert(x)                                                        \
    do {                                                                       \
        if (unlikely (x)) {                                                    \
            const char *errstr = strerror (x);                                 \
            fprintf (stderr, "%s (%s:%d)\n", errstr, __FILE__, __LINE__);      \
            fflush (stderr);                                                   \
            zmq::zmq_abort (errstr);                                           \
        }                                                                      \
    } while (false)

//  Provides convenient way to check for errors from getaddrinfo.
#define gai_assert(x)                                                          \
    do {                                                                       \
        if (unlikely (x)) {                                                    \
            const char *errstr = gai_strerror (x);                             \
            fprintf (stderr, "%s (%s:%d)\n", errstr, __FILE__, __LINE__);      \
            fflush (stderr);                                                   \
            zmq::zmq_abort (errstr);                                           \
        }                                                                      \
    } while (false)

//  Provides convenient way to check whether memory allocation have succeeded.
#define alloc_assert(x)                                                        \
    do {                                                                       \
        if (unlikely (!x)) {                                                   \
            fprintf (stderr, "FATAL ERROR: OUT OF MEMORY (%s:%d)\n", __FILE__, \
                     __LINE__);                                                \
            fflush (stderr);                                                   \
            zmq::zmq_abort ("FATAL ERROR: OUT OF MEMORY");                     \
        }                                                                      \
    } while (false)

#endif
