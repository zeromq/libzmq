/*
    Copyright (c) 2020 Contributors as noted in the AUTHORS file

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

#ifndef __ZMQ_COMPAT_HPP_INCLUDED__
#define __ZMQ_COMPAT_HPP_INCLUDED__

#include "precompiled.hpp"
#include <string.h>

#ifdef ZMQ_HAVE_WINDOWS
#define strcasecmp _stricmp
#define strtok_r strtok_s
#else
#ifndef ZMQ_HAVE_STRLCPY
#ifdef ZMQ_HAVE_LIBBSD
#include <bsd/string.h>
#else
static inline size_t
strlcpy (char *dest_, const char *src_, const size_t dest_size_)
{
    size_t remain = dest_size_;
    for (; remain && *src_; --remain, ++src_, ++dest_) {
        *dest_ = *src_;
    }
    return dest_size_ - remain;
}
#endif
#endif
template <size_t size>
static inline int strcpy_s (char (&dest_)[size], const char *const src_)
{
    const size_t res = strlcpy (dest_, src_, size);
    return res >= size ? ERANGE : 0;
}
#endif

#ifndef HAVE_STRNLEN
static inline size_t strnlen (const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (s[i] == '\0')
            return i + 1;
    }

    return len;
}
#endif

#endif
