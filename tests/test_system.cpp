/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

#if defined (ZMQ_HAVE_WINDOWS)
#   include <winsock2.h>
#   include <stdexcept>
#else
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <unistd.h>
#endif

#if defined (ZMQ_HAVE_WINDOWS)

void initialise_network (void)
{
    WSADATA info;
    if (WSAStartup(MAKEWORD(2,0), &info) != 0)
        throw std::runtime_error("Could not start WSA");
}

int close (int fd)
{
    return closesocket (fd);
}

#else

void initialise_network (void)
{
}

#endif

//  This test case stresses the system to shake out known configuration
//  problems. We're direct system calls when necessary. Some code may
//  need wrapping to be properly portable.

int main (void)
{
    initialise_network ();

    //  Check that we have local networking via ZeroMQ
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    void *dealer = zmq_socket (ctx, ZMQ_DEALER);
    if (zmq_bind (dealer, "tcp://127.0.0.1:5670") == -1) {
        printf ("E: Cannot find 127.0.0.1 -- your system does not have local\n");
        printf ("E: networking. Please fix this before running libzmq checks.\n");
        return -1;
    }
    //  Check that we can create 1,000 sockets
    int handle [1000];
    int count;
    for (count = 0; count < 1000; count++) {
        handle [count] = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (handle [count] == -1) {
            printf ("W: Only able to create %d sockets on this box\n", count);
            printf ("I: Tune your system to increase maximum allowed file handles\n");
#if defined (ZMQ_HAVE_OSX)
            printf ("I: On OS/X, run 'ulimit -n 1200' in bash");
#elif defined (ZMQ_HAVE_LINUX)
            printf ("I: On Linux, run 'ulimit -n 1200' in bash");
#endif        
            return -1;
        }
    }
    //  Release the socket handles
    while (count)
        close (handle [count--]);
}
