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

#include "pipe.hpp"

zs::pipe_t::pipe_t () :
    ypipe_t <zs_msg, false, message_pipe_granularity> (false),
    index (-1)
{
}

zs::pipe_t::~pipe_t ()
{
    //  Flush any outstanding messages to the pipe.
    flush ();

    //  Deallocate all the messages in the pipe.
    zs_msg msg;
    while (read (&msg))
        zs_msg_close (&msg);
}

void zs::pipe_t::set_index (int index_)
{
    index = index_;
}

int zs::pipe_t::get_index ()
{
    return index;
}
