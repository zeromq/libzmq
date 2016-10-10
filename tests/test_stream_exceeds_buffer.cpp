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

#if defined (ZMQ_HAVE_WINDOWS)
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   include <stdexcept>
#   define close closesocket
#else
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <unistd.h>
#endif

#include <zmq.h>

int main()
{
    const int msgsize = 8193;
    char sndbuf[msgsize] = "\xde\xad\xbe\xef";
    unsigned char rcvbuf[msgsize];

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(server_sock!=-1);
    int enable = 1;
    int rc = setsockopt (server_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &enable, sizeof(enable));
    assert(rc!=-1);

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(12345);

    rc = bind(server_sock, (struct sockaddr *)&saddr, sizeof(saddr));
    assert(rc!=-1);
    rc = listen(server_sock, 1);
    assert(rc!=-1);

    void *zctx = zmq_ctx_new();
    assert(zctx);
    void *zsock = zmq_socket(zctx, ZMQ_STREAM);
    assert(zsock);
    rc = zmq_connect(zsock, "tcp://127.0.0.1:12345");
    assert(rc!=-1);

    int client_sock = accept(server_sock, NULL, NULL);
    assert(client_sock!=-1);

    rc = close(server_sock);
    assert(rc!=-1);

    rc = send(client_sock, sndbuf, msgsize, 0);
    assert(rc==msgsize);

    zmq_msg_t msg;
    zmq_msg_init(&msg);

    int rcvbytes = 0;
    while (rcvbytes==0) // skip connection notification, if any
    {
        rc = zmq_msg_recv(&msg, zsock, 0);  // peerid
        assert(rc!=-1);
        assert(zmq_msg_more(&msg));
        rcvbytes = zmq_msg_recv(&msg, zsock, 0);
        assert(rcvbytes!=-1);
        assert(!zmq_msg_more(&msg));
    }

    // for this test, we only collect the first chunk
    // since the corruption already occurs in the first chunk
    memcpy(rcvbuf, zmq_msg_data(&msg), zmq_msg_size(&msg));

    zmq_msg_close(&msg);
    zmq_close(zsock);
    close(client_sock);

    zmq_ctx_destroy(zctx);

    assert(rcvbytes >= 4);

    // notice that only the 1st byte gets corrupted
    assert(rcvbuf[3]==0xef);
    assert(rcvbuf[2]==0xbe);
    assert(rcvbuf[1]==0xad);
    assert(rcvbuf[0]==0xde);

    (void)(rc); // avoid -Wunused-but-set-variable warning in release build
}

