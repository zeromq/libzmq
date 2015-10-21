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

#include "socket_poller.hpp"
#include "err.hpp"

zmq::socket_poller_t::socket_poller_t () :
    tag (0xCAFEBABE),
    poll_set (NULL),
    poll_events (NULL)
{
    pollfd = zmq_pollfd_new ();    
}

zmq::socket_poller_t::~socket_poller_t ()
{
    //  Mark the socket_poller as dead
    tag = 0xdeadbeef;    

    zmq_pollfd_close (pollfd);

    if (poll_set) {
        free (poll_set);    
        poll_set = NULL;
    }

    if (poll_events) {
        free (poll_events);
        poll_events = NULL;
    }
}

bool zmq::socket_poller_t::check_tag () 
{
    return tag == 0xCAFEBABE;
}

int zmq::socket_poller_t::add_socket (void *socket_, void* user_data_) 
{
    for (events_t::iterator it = events.begin (); it != events.end (); ++it) {
        if (it->socket == socket_) {
            errno = EINVAL;
            return -1;
        }            
    }

    int thread_safe;
    size_t thread_safe_size = sizeof(int);
    
    if (zmq_getsockopt (socket_, ZMQ_THREAD_SAFE, &thread_safe, &thread_safe_size) == -1)
        return -1;

    if (thread_safe) {
        if (zmq_add_pollfd (socket_, pollfd) == -1)
           return -1;
    }
    
    event_t event = {socket_, 0, user_data_};
    events.push_back (event);
    need_rebuild = true;

    return 0;
}

#if defined _WIN32
int zmq::socket_poller_t::add_fd (SOCKET fd_, void *user_data_)
#else 
int zmq::socket_poller_t::add_fd (int fd_, void *user_data_)
#endif
{
   for (events_t::iterator it = events.begin (); it != events.end (); ++it) {
        if (!it->socket && it->fd == fd_) {
            errno = EINVAL;
            return -1;
        }            
    }

    event_t event = {NULL, fd_, user_data_};
    events.push_back (event);
    need_rebuild = true;

    return 0;
}

int zmq::socket_poller_t::remove_socket (void* socket_)
{
    events_t::iterator it;

    for (it = events.begin (); it != events.end (); ++it) {
        if (it->socket == socket_)
            break;
    }

    if (it == events.end()) {
        errno = EINVAL;
        return -1;
    }
     
    int thread_safe;
    size_t thread_safe_size = sizeof(int);

    if (zmq_getsockopt (socket_, ZMQ_THREAD_SAFE, &thread_safe, &thread_safe_size) == -1)
        return -1;

    if (thread_safe) {
        if (zmq_remove_pollfd (socket_, pollfd) == -1)
            return -1;
    }
    
    events.erase (it);
    need_rebuild = true;    
    
    return 0;
}

#if defined _WIN32
int zmq::socket_poller_t::remove_fd (SOCKET fd_)
#else 
int zmq::socket_poller_t::remove_fd (int fd_)
#endif
{
    events_t::iterator it;

    for (it = events.begin (); it != events.end (); ++it) {
        if (!it->socket && it->fd == fd_)
            break;
    }

    if (it == events.end()) {
        errno = EINVAL;
        return -1;
    }
 
    events.erase (it);
    need_rebuild = true;

    return 0;
} 

int zmq::socket_poller_t::wait (zmq::socket_poller_t::event_t *event_, long timeout_)
{
    if (need_rebuild)
        rebuild ();

    int rc = zmq_pollfd_poll (pollfd, poll_set, poll_size, timeout_);

    if (rc == -1) {
        return rc;
    }

    if (rc == 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    for (int i = 0; i < poll_size; i++) {
        if (poll_set [i].revents & ZMQ_POLLIN) {        
            *event_ = poll_events[i];           

            break;
        }
    }
    
    return 0;
}

void zmq::socket_poller_t::rebuild () 
{
    if (poll_set) {
        free (poll_set);
        poll_set = NULL;
    }

    if (poll_events) {
        free (poll_events);
        poll_events = NULL;
    }

    poll_size = events.size ();
    
    poll_set = (zmq_pollitem_t*) malloc (poll_size * sizeof (zmq_pollitem_t));
    alloc_assert (poll_set);

    poll_events = (event_t*) malloc (poll_size * sizeof (event_t));

    int event_nbr = 0;
    for (events_t::iterator it = events.begin (); it != events.end (); ++it, event_nbr++) {
        poll_set [event_nbr].socket = it->socket;        

        if (!it->socket)
            poll_set [event_nbr].fd = it->fd;

        poll_set [event_nbr].events = ZMQ_POLLIN;
        poll_events [event_nbr] = *it;
    }

    need_rebuild = false;
}
