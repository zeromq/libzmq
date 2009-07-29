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

#ifndef __ZS_SESSION_STUB_HPP_INCLUDED__
#define __ZS_SESSION_STUB_HPP_INCLUDED__

#include <string>

#include "i_session.hpp"

namespace zs
{

    //  This class is used instead of regular session till the identity of
    //  incomming connection is established and connection is attached
    //  to corresponding session.

    class session_stub_t : public i_session
    {
    public:

        session_stub_t (class listener_t *listener_);

        //  i_session implementation.
        void set_engine (struct i_engine *engine_);
        void terminate ();
        void shutdown ();
        bool read (struct zs_msg *msg_);
        bool write (struct zs_msg *msg_);
        void flush ();

        //  Detaches engine from the stub. Returns it to the caller.
        struct i_engine *detach_engine ();

        //  Manipulate stubs's index in listener's array of stubs.
        void set_index (int index_);
        int get_index ();

    private:

        //  Clean-up.
        virtual ~session_stub_t ();

        enum {
            reading_identity,
            has_identity
        } state;

        //  Reference to the associated engine.
        i_engine *engine;

        //  Reference to the listener object that owns this stub.
        class listener_t *listener;

        //  Index of the stub in listener's array of stubs.
        int index;

        //  Identity of the connection.
        std::string identity;

        session_stub_t (const session_stub_t&);
        void operator = (const session_stub_t&);
    };

}

#endif
