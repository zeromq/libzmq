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

#ifndef __ZS_SOCKET_BASE_HPP_INCLUDED__
#define __ZS_SOCKET_BASE_HPP_INCLUDED__

#include <vector>

#include "i_engine.hpp"
#include "i_api.hpp"
#include "object.hpp"

namespace zs
{

    class socket_base_t : public object_t, public i_engine, public i_api
    {
    public:

        //  TODO: Possibly, session can be attached to the engine using
        //  attach function.
        socket_base_t (class app_thread_t *thread_, class session_t *session_);

        //  i_engine interface implementation.
        void attach (struct i_poller *poller_, struct i_session *session_);
        void detach ();
        void revive ();
        void schedule_terminate ();
        void terminate ();
        void shutdown ();

        // i_api interface implementation.
        int bind (const char *addr_, struct zs_opts *opts_);
        int connect (const char *addr_, struct zs_opts *opts_);
        int subscribe (const char *criteria_);
        int send (struct zs_msg *msg_, int flags_);
        int flush ();
        int recv (struct zs_msg *msg_, int flags_);
        int close ();

    protected:

        //  Clean-up. The function has to be protected rather than private,
        //  otherwise auto-generated destructor in derived classes
        //  cannot be compiled. It has to be virtual so that socket_base_t's
        //  terminate & shutdown functions deallocate correct type of object.
        virtual ~socket_base_t ();

        //  By default, socket is able to pass messages in both inward and
        //  outward directions. By calling these functions, particular
        //  socket type is able to eliminate one direction.
        void disable_in ();
        void disable_out ();

    private:

        //  Pointer to the application thread the socket belongs to.
        class app_thread_t *thread;

        //  Pointer to the associated session object.
        class session_t *session;

        //  List of I/O object created via this socket. These have to be shut
        //  down when the socket is closed.
        typedef std::vector <class io_object_t*> io_objects_t;
        io_objects_t io_objects;

        //  If true, socket creates inbound pipe when binding to an engine.
        bool has_in;

        //  If true, socket creates outbound pipe when binding to an engine.
        bool has_out;

        socket_base_t (const socket_base_t&);
        void operator = (const socket_base_t&);
    };

}

#endif
