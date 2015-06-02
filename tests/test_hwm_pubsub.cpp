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

#include "testutil.hpp"

// const int MAX_SENDS = 10000;

int test_defaults (int send_hwm, int msgCnt)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    // Set up bind socket
    void *pub_socket = zmq_socket (ctx, ZMQ_PUB);
    assert (pub_socket);
    rc = zmq_bind (pub_socket, "inproc://a");
    assert (rc == 0);

    // Set up connect socket
    void *sub_socket = zmq_socket (ctx, ZMQ_SUB);
    assert (sub_socket);
    rc = zmq_connect (sub_socket, "inproc://a");
    assert (rc == 0);

    //set a hwm on publisher
    rc = zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
    rc = zmq_setsockopt( sub_socket, ZMQ_SUBSCRIBE, 0, 0);

    // Send until we block
    int send_count = 0;
    while (send_count < msgCnt && zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT) == 0)
        ++send_count;

    // Now receive all sent messages
    int recv_count = 0;
    while (0 == zmq_recv (sub_socket, NULL, 0, ZMQ_DONTWAIT))
    {
        ++recv_count;
    }

    assert (send_hwm == recv_count);

    // Clean up
    rc = zmq_close (sub_socket);
    assert (rc == 0);

    rc = zmq_close (pub_socket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return recv_count;
}

int receive( void* socket)
{
  int recv_count = 0;
  // Now receive all sent messages
  while (0 == zmq_recv (socket, NULL, 0, ZMQ_DONTWAIT))
  {
      ++recv_count;
  }

  return recv_count;

}


int test_blocking (int send_hwm, int msgCnt)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;

    // Set up bind socket
    void *pub_socket = zmq_socket (ctx, ZMQ_PUB);
    assert (pub_socket);
    rc = zmq_bind (pub_socket, "inproc://a");
    assert (rc == 0);

    // Set up connect socket
    void *sub_socket = zmq_socket (ctx, ZMQ_SUB);
    assert (sub_socket);
    rc = zmq_connect (sub_socket, "inproc://a");
    assert (rc == 0);

    //set a hwm on publisher
    rc = zmq_setsockopt (pub_socket, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm));
    int wait = 1;
    rc = zmq_setsockopt (pub_socket, ZMQ_XPUB_NODROP, &wait, sizeof(wait));
    rc = zmq_setsockopt( sub_socket, ZMQ_SUBSCRIBE, 0, 0);

    // Send until we block
    int send_count = 0;
    int recv_count = 0;
    while (send_count < msgCnt )
    {
        rc = zmq_send (pub_socket, NULL, 0, ZMQ_DONTWAIT);
        if( rc == 0)
        {
            ++send_count;
        }
        else if( -1 == rc)
        {
            assert(EAGAIN == errno);
            recv_count += receive(sub_socket);
            assert(recv_count == send_count);
        }
    }

    recv_count += receive(sub_socket);

    // Clean up
    rc = zmq_close (sub_socket);
    assert (rc == 0);

    rc = zmq_close (pub_socket);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return recv_count;
}



int main (void)
{
    setup_test_environment();

    int count;

    // send 1000 msg on hwm 1000, receive 1000
    count = test_defaults (1000,1000);
    assert (count == 1000);

   // send 6000 msg on hwm 2000, drops above hwm, only receive hwm
    count = test_blocking (2000,6000);
    assert (count == 6000);

    return 0;
}
