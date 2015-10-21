/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_SOCKET_POLLER_HPP_INCLUDED__
#define __ZMQ_SOCKET_POLLER_HPP_INCLUDED__

#include <vector>
#include <algorithm>

#include "../include/zmq.h"

namespace zmq
{

    class socket_poller_t
    {
    public:
        socket_poller_t ();
        ~socket_poller_t ();

        typedef struct event_t
        {
            void *socket;
#if defined _WIN32
            SOCKET fd;
#else
            int fd;
#endif
            void *user_data; 
            short events;
        } event_t;

        int add_socket (void *socket, void *user_data, short events);
        int modify_socket (void *socket, short events);
        int remove_socket (void *socket);
#if defined _WIN32
        int add_fd (SOCKET fd, void *user_data, short events);
        int modify_fd (SOCKET fd, short events);
        int remove_fd (SOCKET fd);
#else
        int add_fd (int fd, void *user_data, short events);
        int modify_fd (int fd, short events);
        int remove_fd (int fd);
#endif

        int wait (event_t *event, long timeout);

        //  Return false if object is not a socket.
        bool check_tag ();

    private:
        void rebuild ();

        //  Used to check whether the object is a socket_poller.
        uint32_t tag;

        //  Pollfd used for thread safe sockets polling
        void *pollfd;

        //  List of sockets
        typedef std::vector <event_t> events_t;
        events_t events;

        //  Current zmq_poll set
        zmq_pollitem_t *poll_set;

        //  Matching set to events
        event_t *poll_events;

        //  Size of the pollset
        int poll_size;

        //  Does the pollset needs rebuilding?
        bool need_rebuild;
        
        socket_poller_t (const socket_poller_t&);
        const socket_poller_t &operator = (const socket_poller_t&);
    };

}

#endif
