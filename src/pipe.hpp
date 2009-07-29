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

#ifndef __ZS_PIPE_HPP_INCLUDED__
#define __ZS_PIPE_HPP_INCLUDED__

#include "../include/zs.h"

#include "ypipe.hpp"
#include "config.hpp"

namespace zs
{

    //  Message pipe. A simple wrapper on top of ypipe.

    class pipe_t : public ypipe_t <zs_msg, false, message_pipe_granularity>
    {
        //  Dispatcher is a friend so that it can create & destroy the pipes.
        //  By making constructor & destructor private we are sure that nobody
        //  except dispatcher messes with pipes.
        friend class dispatcher_t;

    private:

        pipe_t ();
        ~pipe_t ();

        void set_index (int index_);
        int get_index ();

        //  Index of the pipe in dispatcher's array of pipes.
        int index;

        pipe_t (const pipe_t&);
        void operator = (const pipe_t&);
    }; 

}

#endif
