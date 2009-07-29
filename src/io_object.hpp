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

#ifndef __ZS_IO_OBJECT_HPP_INCLUDED__
#define __ZS_IO_OBJECT_HPP_INCLUDED__

#include "object.hpp"

namespace zs
{

    //  All objects running within the context of an I/O thread should be
    //  derived from this class to allow owning application threads to
    //  destroy them.

    class io_object_t : public object_t
    {
    public:

        io_object_t (class io_thread_t *thread_);
        ~io_object_t ();

        virtual void terminate () = 0;
        virtual void shutdown () = 0;

        struct i_poller *get_poller ();

    private:
 
        class io_thread_t *thread;
    };

}

#endif
