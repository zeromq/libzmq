/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZS_UUID_HPP_INCLUDED__
#define __ZS_UUID_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZS_HAVE_WINDOWS
#include <rpcdce.h>
#elif defined ZS_HAVE_FREEBSD
#include <uuid.h>
#elif defined ZS_HAVE_LINUX || defined ZS_HAVE_SOLARIS || defined ZS_HAVE_OSX
#include <uuid/uuid.h>
#else
#include <stdint.h>
#endif

namespace zs
{

    //  This class provides RFC 4122 (a Universally Unique IDentifier)
    //  implementation.

    class uuid_t
    {
    public:

        uuid_t ();
        ~uuid_t ();

        //  Returns a pointer to buffer containing the textual
        //  representation of the UUID. The caller is reponsible to
        //  free the allocated memory.
        const char *to_string ();

    private:

        //  The length of textual representation of UUID.
        enum { uuid_string_len = 36 };

#if defined ZS_HAVE_WINDOWS
        ::UUID uuid;
        char *uuid_str;
#elif defined ZS_HAVE_FREEBSD
        ::uuid_t uuid;
        char *uuid_str;
#elif defined ZS_HAVE_LINUX || defined ZS_HAVE_SOLARIS || defined ZS_HAVE_OSX
        ::uuid_t uuid;
        char uuid_buf [uuid_string_len + 1];
#else
        //  RFC 4122 UUID's fields
        uint32_t time_low;
        uint16_t time_mid;
        uint16_t time_hi_and_version;
        uint8_t clock_seq_hi_and_reserved;
        uint8_t clock_seq_low;
        uint8_t node [6];

        char uuid_buf [uuid_string_len + 1];
#endif
    };

}

#endif
