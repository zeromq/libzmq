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

#include "testutil.hpp"

#define MSG_SIZE 20

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

int main (void)
{
    int rc;

    setup_test_environment();
    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);
    void *req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    rc = zmq_bind(rep, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    rc = zmq_connect(req, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    char tmp[MSG_SIZE];
    memset (tmp, 0, MSG_SIZE);
    zmq_send(req, tmp, MSG_SIZE, 0);

    zmq_msg_t msg;
    rc = zmq_msg_init(&msg);
    assert (rc == 0);

    zmq_recvmsg(rep, &msg, 0);
    assert(zmq_msg_size(&msg) == MSG_SIZE);

    // get the messages source file descriptor
    int srcFd = zmq_msg_get(&msg, ZMQ_SRCFD);
    assert(srcFd >= 0);

    rc = zmq_msg_close(&msg);
    assert (rc == 0);

    // get the remote endpoint
    struct sockaddr_storage ss;
#ifdef ZMQ_HAVE_HPUX
    int addrlen = sizeof ss;
#else
    socklen_t addrlen = sizeof ss;
#endif
    rc = getpeername (srcFd, (struct sockaddr*) &ss, &addrlen);
    assert (rc == 0);

    char host [NI_MAXHOST];
    rc = getnameinfo ((struct sockaddr*) &ss, addrlen, host, sizeof host,
            NULL, 0, NI_NUMERICHOST);
    assert (rc == 0);

    // assert it is localhost which connected
    assert (strcmp(host, "127.0.0.1") == 0);

    rc = zmq_close (rep);
    assert (rc == 0);
    rc = zmq_close (req);
    assert (rc == 0);

    // sleep a bit for the socket to be freed
    msleep (SETTLE_TIME);

    // getting name from closed socket will fail
    rc = getpeername (srcFd, (struct sockaddr*) &ss, &addrlen);
#ifdef ZMQ_HAVE_WINDOWS
    assert (rc == SOCKET_ERROR);
    assert (WSAGetLastError() == WSAENOTSOCK);
#else
    assert (rc == -1);
    assert (errno == EBADF);
#endif

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0 ;
}

