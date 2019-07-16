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

#ifndef __ZMQ_STDINT_HPP_INCLUDED__
#define __ZMQ_STDINT_HPP_INCLUDED__

#if defined ZMQ_HAVE_SOLARIS || defined ZMQ_HAVE_OPENVMS

#include <inttypes.h>

#elif defined _MSC_VER && _MSC_VER < 1600

#ifndef int8_t
typedef __int8 int8_t;
#endif
#ifndef int16_t
typedef __int16 int16_t;
#endif
#ifndef int32_t
typedef __int32 int32_t;
#endif
#ifndef int64_t
typedef __int64 int64_t;
#endif
#ifndef uint8_t
typedef unsigned __int8 uint8_t;
#endif
#ifndef uint16_t
typedef unsigned __int16 uint16_t;
#endif
#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif
#ifndef uint64_t
typedef unsigned __int64 uint64_t;
#endif
#ifndef UINT16_MAX
#define UINT16_MAX _UI16_MAX
#endif
#ifndef UINT32_MAX
#define UINT32_MAX _UI32_MAX
#endif

#else

#include <stdint.h>

#endif

#ifndef UINT8_MAX
#define UINT8_MAX 0xFF
#endif

#endif
