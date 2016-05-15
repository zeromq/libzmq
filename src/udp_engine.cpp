/*
Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#include "precompiled.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "udp_engine.hpp"
#include "session_base.hpp"
#include "v2_protocol.hpp"
#include "err.hpp"
#include "ip.hpp"

zmq::udp_engine_t::udp_engine_t(const options_t &options_) :
    plugged (false),
    fd(-1),
    session(NULL),
    handle(NULL),
    address(NULL),
    options(options_),
    send_enabled(false),
    recv_enabled(false)
{
}

zmq::udp_engine_t::~udp_engine_t()
{
    zmq_assert (!plugged);

    if (fd != retired_fd) {
#ifdef ZMQ_HAVE_WINDOWS
        int rc = closesocket (fd);
        wsa_assert (rc != SOCKET_ERROR);
#else
        int rc = close (fd);
        errno_assert (rc == 0);
#endif
        fd = retired_fd;
    }
}

int zmq::udp_engine_t::init (address_t *address_, bool send_, bool recv_)
{
    zmq_assert (address_);
    zmq_assert (send_ || recv_);
    send_enabled = send_;
    recv_enabled = recv_;
    address = address_;

    fd = open_socket (address->resolved.udp_addr->family (), SOCK_DGRAM, IPPROTO_UDP);
    if (fd == retired_fd)
        return -1;

    unblock_socket (fd);

    return 0;
}

void zmq::udp_engine_t::plug (io_thread_t* io_thread_, session_base_t *session_)
{
    zmq_assert (!plugged);
    plugged = true;

    zmq_assert (!session);
    zmq_assert (session_);
    session = session_;

    //  Connect to I/O threads poller object.
    io_object_t::plug (io_thread_);
    handle = add_fd (fd);

    if (send_enabled)
        set_pollout (handle);

    if (recv_enabled) {
        int on = 1;
        int rc = setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof (on));
#ifdef ZMQ_HAVE_WINDOWS
        wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif

        rc = bind (fd, address->resolved.udp_addr->bind_addr (),
                       address->resolved.udp_addr->bind_addrlen ());
#ifdef ZMQ_HAVE_WINDOWS
        wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif

        if (address->resolved.udp_addr->is_mcast ()) {
            struct ip_mreq mreq;
            mreq.imr_multiaddr = address->resolved.udp_addr->multicast_ip ();
            mreq.imr_interface = address->resolved.udp_addr->interface_ip ();
            rc = setsockopt (fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof (mreq));
#ifdef ZMQ_HAVE_WINDOWS
            wsa_assert (rc != SOCKET_ERROR);
#else
            errno_assert (rc == 0);
#endif
        }
        set_pollin (handle);

        //  Call restart output to drop all join/leave commands
        restart_output ();
    }
}

void zmq::udp_engine_t::terminate()
{
    zmq_assert (plugged);
    plugged = false;

    rm_fd (handle);

    //  Disconnect from I/O threads poller object.
    io_object_t::unplug ();

    delete this;
}

void zmq::udp_engine_t::out_event()
{
    msg_t group_msg;
    int rc = session->pull_msg (&group_msg);
    errno_assert (rc == 0 || (rc == -1 && errno == EAGAIN));

    if (rc == 0) {
        msg_t body_msg;
        rc = session->pull_msg (&body_msg);

        size_t group_size = group_msg.size ();
        size_t body_size = body_msg.size ();
        size_t size = group_size + body_size + 1;

        struct sockaddr* out_address = (struct sockaddr*) address->resolved.udp_addr->dest_addr ();
        socklen_t out_addrlen = address->resolved.udp_addr->dest_addrlen ();
        
        if (options.raw_socket) {
            if (group_size > 0) {
                out_address = (struct sockaddr*) group_msg.data();  
                out_addrlen = group_size;
                size = body_size;
            }
            memcpy (out_buffer, body_msg.data (), body_size);
        }
        else {
            // TODO: check if larger than maximum size
            out_buffer[0] = (unsigned char) group_size;
            memcpy (out_buffer + 1, group_msg.data (), group_size);
            memcpy (out_buffer + 1 + group_size, body_msg.data (), body_size);
        }

        rc = group_msg.close ();
        errno_assert (rc == 0);

        body_msg.close ();
        errno_assert (rc == 0);

#ifdef ZMQ_HAVE_WINDOWS
        rc = sendto (fd, (const char *) out_buffer, (int) size, 0,
            address->resolved.udp_addr->dest_addr (),
            (int) address->resolved.udp_addr->dest_addrlen ());
        wsa_assert (rc != SOCKET_ERROR);
#else
        rc = sendto (fd, out_buffer, size, 0, out_address, out_addrlen);
        errno_assert (rc != -1);
#endif
    }
    else
       reset_pollout (handle);
}

void zmq::udp_engine_t::restart_output()
{
    //  If we don't support send we just drop all messages
    if (!send_enabled) {
        msg_t msg;
        while (session->pull_msg (&msg) == 0)
            msg.close ();
    }
    else {
        set_pollout(handle);
        out_event ();
    }
}

void zmq::udp_engine_t::in_event()
{
  struct sockaddr_in in_address;
  socklen_t in_addrlen;
#ifdef ZMQ_HAVE_WINDOWS
    int nbytes = recvfrom(fd, (char*) in_buffer, MAX_UDP_MSG, 0, (sockaddr*) &address, &addrlen);
    const int last_error = WSAGetLastError();
    if (nbytes == SOCKET_ERROR) {
        wsa_assert(
            last_error == WSAENETDOWN ||
            last_error == WSAENETRESET ||
            last_error == WSAEWOULDBLOCK);
        return;
    }
#else
    int nbytes = recvfrom(fd, in_buffer, MAX_UDP_MSG, 0, (sockaddr*) &in_address, &in_addrlen);
    if (nbytes == -1) {
        errno_assert(errno != EBADF
            && errno != EFAULT
            && errno != ENOMEM
            && errno != ENOTSOCK);
        return;
    }
#endif

    void* group_buffer;
    int group_size;
    int body_size;
    msg_t msg;
    
    if (options.raw_socket) {
        group_buffer = (void*) &(in_address);
        group_size = in_addrlen;
      
        body_size = nbytes - 1;
    }
    else {
        group_buffer = in_buffer + 1;
        group_size = in_buffer[0];

        //  This doesn't fit, just ingore
        if (nbytes - 1 < group_size)
            return;

        body_size = nbytes - 1 - group_size;
    }
    
    int rc = msg.init_size (group_size);
    errno_assert (rc == 0);
    msg.set_flags (msg_t::more);
    memcpy (msg.data (), group_buffer, group_size);
    
    rc = session->push_msg (&msg);
    errno_assert (rc == 0 || (rc == -1 && errno == EAGAIN));

    //  Pipe is full
    if (rc != 0) {
        rc = msg.close ();
        errno_assert (rc == 0);

        reset_pollin (handle);
        return;
    }

    rc = msg.close ();
    errno_assert (rc == 0);
    rc = msg.init_size (body_size);
    errno_assert (rc == 0);
    memcpy (msg.data (), in_buffer + 1 + group_size, body_size);
    rc = session->push_msg (&msg);
    errno_assert (rc == 0);
    rc = msg.close ();
    errno_assert (rc == 0);
    session->flush ();
}

void zmq::udp_engine_t::restart_input()
{
    if (!recv_enabled)
        return;

    set_pollin (handle);
    in_event ();
}
