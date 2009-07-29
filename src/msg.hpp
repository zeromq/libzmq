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

#ifndef __ZS_MSG_HPP_INCLUDE__
#define __ZS_MSG_HPP_INCLUDE__

#include <stddef.h>

#include "../include/zs.h"

#include "atomic_counter.hpp"

//namespace zs
//{

    //  Shared message buffer. Message data are either allocated in one
    //  continguous block along with this structure - thus avoiding one
    //  malloc/free pair or they are stored in used-supplied memory.
    //  In the latter case, ffn member stores pointer to the function to be
    //  used to deallocate the data. If the buffer is actually shared (there
    //  are at least 2 references to it) refcount member contains number of
    //  references.
    struct zs_msg_content
    {
        void *data;
        size_t size;
        zs_free_fn *ffn;
        zs::atomic_counter_t refcnt;
    };

//}

#endif
