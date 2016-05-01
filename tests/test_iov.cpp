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

// XSI vector I/O
#if defined ZMQ_HAVE_UIO
#include <sys/uio.h>
#else
struct iovec {
    void *iov_base;
    size_t iov_len;
};
#endif

void do_check(void* sb, void* sc, size_t msg_size)
{
    assert (sb && sc && msg_size > 0);

    int rc = 0;
    const char msg_val = '1';
    const int num_messages = 10;
    size_t send_count, recv_count;

    send_count = recv_count = num_messages;

    char *ref_msg = (char *) malloc (msg_size);
    assert (ref_msg);
    memset (ref_msg, msg_val, msg_size);

    // zmq_sendiov(3) as a single multi-part send
    struct iovec send_iov[num_messages];
    char *buf = (char *) malloc (msg_size * num_messages);

    for (int i = 0; i < num_messages; i++)
    {
        send_iov[i].iov_base = &buf[i * msg_size];
        send_iov[i].iov_len = msg_size;
        memcpy (send_iov[i].iov_base, ref_msg, msg_size);
        assert (memcmp (ref_msg, send_iov[i].iov_base, msg_size) == 0);
    }

    // Test errors - zmq_recviov - null socket
    rc = zmq_sendiov (NULL, send_iov, send_count, ZMQ_SNDMORE);
    assert (rc == -1 && errno == ENOTSOCK);
    // Test errors - zmq_recviov - invalid send count
    rc = zmq_sendiov (sc, send_iov, 0, 0);
    assert (rc == -1 && errno == EINVAL);
    // Test errors - zmq_recviov - null iovec
    rc = zmq_sendiov (sc, NULL, send_count, 0);
    assert (rc == -1 && errno == EINVAL);

    // Test success
    rc = zmq_sendiov (sc, send_iov, send_count, ZMQ_SNDMORE);
    // The zmq_sendiov(3) API method does not follow the same semantics as
    // zmq_recviov(3); the latter returns the count of messages sent, rightly
    // so, whilst the former sends the number of bytes successfully sent from
    // the last message, which does not hold much sense from a batch send
    // perspective; hence the assert checks if rc is same as msg_size.
    assert ((size_t)rc == msg_size);

    // zmq_recviov(3) single-shot
    struct iovec recv_iov[num_messages];

    // Test errors - zmq_recviov - null socket
    rc = zmq_recviov (NULL, recv_iov, &recv_count, 0);
    assert (rc == -1 && errno == ENOTSOCK);
    // Test error - zmq_recviov - invalid receive count
    rc = zmq_recviov (sb, recv_iov, NULL, 0);
    assert (rc == -1 && errno == EINVAL);
    size_t invalid_recv_count = 0;
    rc = zmq_recviov (sb, recv_iov, &invalid_recv_count, 0);
    assert (rc == -1 && errno == EINVAL);
    // Test error - zmq_recviov - null iovec
    rc = zmq_recviov (sb, NULL, &recv_count, 0);
    assert (rc == -1 && errno == EINVAL);

    // Test success
    rc = zmq_recviov (sb, recv_iov, &recv_count, 0);
    assert (rc == num_messages);

    for (int i = 0; i < num_messages; i++)
    {
        assert (recv_iov[i].iov_base);
        assert (memcmp (ref_msg, recv_iov[i].iov_base, msg_size) == 0);
        free(recv_iov[i].iov_base);
    }

    assert (send_count == recv_count);
    free (ref_msg);
    free (buf);
}

int main (void)
{
    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);
    int rc;
   
    void *sb = zmq_socket (ctx, ZMQ_PULL);
    assert (sb);
  
    rc = zmq_bind (sb, "inproc://a");
    assert (rc == 0);

    msleep (SETTLE_TIME);
    void *sc = zmq_socket (ctx, ZMQ_PUSH);
  
    rc = zmq_connect (sc, "inproc://a");
    assert (rc == 0);


    // message bigger than VSM max
    do_check (sb, sc, 100);

    // message smaller than VSM max
    do_check (sb, sc, 10);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
