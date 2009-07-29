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

#ifndef __ZS_I_THREAD_HPP_INCLUDED__
#define __ZS_I_THREAD_HPP_INCLUDED__

namespace zs
{

    //  Interface used by session object to communicate with the thread
    //  it belongs to.

    struct i_thread
    {
        virtual void attach_session (class session_t *session_) = 0;
        virtual void detach_session (class session_t *session_) = 0;
        virtual struct i_poller *get_poller () = 0;
    };

}

#endif
