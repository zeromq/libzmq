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

#ifndef __ZS_I_ENGINE_HPP_INCLUDED__
#define __ZS_I_ENGINE_HPP_INCLUDED__

namespace zs
{

    //  Generic interface to access engines from MD objects.

    struct i_engine
    {
        //  Attach the engine with specified context.
        virtual void attach (struct i_poller *poller_,
            struct i_session *session_) = 0;

        //  Detach the engine from the current context.
        virtual void detach () = 0;

        //  Notify the engine that new messages are available.
        virtual void revive () = 0;

        //  Called by session when it decides the engine
        //  should terminate itself.
        virtual void schedule_terminate () = 0;

        //  Called by normal object termination process.
        virtual void terminate () = 0;

        //  To be called by MD when terminal shutdown (zs_term) is in progress.
        virtual void shutdown () = 0;
    };

}

#endif
