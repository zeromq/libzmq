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

#ifndef __ZMQ_PLATFORM_HPP_INCLUDED__
#define __ZMQ_PLATFORM_HPP_INCLUDED__

//  This file provides the configuration for Linux, Windows, and OS/X
//  as determined by ZMQ_HAVE_XXX macros passed from project.gyp

//  Check that we're being called from our gyp makefile
#ifndef ZMQ_GYP_BUILD
#   error "foreign platform.hpp detected, please re-configure"
#endif

//  Set for all platforms
#define ZMQ_HAVE_CURVE 1
#define ZMQ_USE_TWEETNACL 1

#if defined ZMQ_HAVE_WINDOWS
#   define ZMQ_USE_SELECT 1

#elif defined ZMQ_HAVE_OSX
#   define ZMQ_USE_KQUEUE 1
#   define HAVE_POSIX_MEMALIGN 1
#   define ZMQ_HAVE_IFADDRS 1
#   define ZMQ_HAVE_SO_KEEPALIVE 1
#   define ZMQ_HAVE_TCP_KEEPALIVE 1
#   define ZMQ_HAVE_TCP_KEEPCNT 1
#   define ZMQ_HAVE_TCP_KEEPINTVL 1
#   define ZMQ_HAVE_UIO 1
#   define HAVE_FORK 1

#elif defined ZMQ_HAVE_LINUX
#   define ZMQ_USE_EPOLL 1
#   define HAVE_POSIX_MEMALIGN 1
#   define ZMQ_HAVE_EVENTFD 1
#   define ZMQ_HAVE_IFADDRS 1
#   define ZMQ_HAVE_SOCK_CLOEXEC 1
#   define ZMQ_HAVE_SO_KEEPALIVE 1
#   define ZMQ_HAVE_SO_PEERCRED 1
#   define ZMQ_HAVE_TCP_KEEPCNT 1
#   define ZMQ_HAVE_TCP_KEEPIDLE 1
#   define ZMQ_HAVE_TCP_KEEPINTVL 1
#   define ZMQ_HAVE_UIO 1
#   define HAVE_CLOCK_GETTIME 1
#   define HAVE_FORK 1

#else
#   error "No platform defined, abandoning"
#endif

#endif
