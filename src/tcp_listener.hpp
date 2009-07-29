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

#ifndef __ZS_TCP_LISTENER_HPP_INCLUDED__
#define __ZS_TCP_LISTENER_HPP_INCLUDED__

#include "fd.hpp"

namespace zs
{

    //  The class encapsulating simple TCP listening socket.

    class tcp_listener_t
    {
    public:

        tcp_listener_t ();
        ~tcp_listener_t ();

        //  Open TCP listining socket. Address is in
        //  <interface-name>:<port-number> format. Interface name may be '*'
        //  to bind to all the interfaces.
        int open (const char *addr_);

        //  Close the listening socket.
        int close ();

        //  Get the file descriptor to poll on to get notified about
        //  newly created connections.
        fd_t get_fd ();

        //  Accept the new connection. Returns the file descriptor of the
        //  newly created connection. The function may return retired_fd
        //  if the connection was dropped while waiting in the listen backlog.
        fd_t accept ();

    private:

        //  Underlying socket.
        fd_t s;

        tcp_listener_t (const tcp_listener_t&);
        void operator = (const tcp_listener_t&);
    };

}

#endif
