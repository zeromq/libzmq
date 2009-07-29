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

#ifndef __ZS_I_DEMUX_HPP_INCLUDED__
#define __ZS_I_DEMUX_HPP_INCLUDED__

namespace zs
{

    struct i_demux
    {
        //  Attaches mux to a particular session.
        virtual void set_session (class session_t *session_) = 0;

        //  To be called when the whole infrastrucure is being closed (zs_term).
        virtual void shutdown () = 0;

        //  To be called when session is being closed.
        virtual void terminate () = 0;

        //  Adds new pipe to the demux to send messages to.
        virtual void attach_pipe (class pipe_writer_t *pipe_) = 0;

        //  Removes pipe from the demux.
        virtual void detach_pipe (class pipe_writer_t *pipe_) = 0;

        //  Returns true if there's no pipe attached.
        virtual bool empty () = 0;

        //  Sends the message. Returns false if the message cannot be sent
        //  because the pipes are full.
        virtual bool send (struct zs_msg *msg_) = 0;

        //  Flushes messages downstream.
        virtual void flush () = 0;
    };

}

#endif
