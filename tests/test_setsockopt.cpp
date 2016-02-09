#include "testutil.hpp"

void test_setsockopt_tcp_recv_buffer (void)
{
    int rc;
    void *ctx = zmq_ctx_new ();
    void *socket = zmq_socket (ctx, ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    rc = zmq_getsockopt (socket, ZMQ_RCVBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 8192);

    rc = zmq_setsockopt (socket, ZMQ_RCVBUF, &val, sizeof (val));
    assert (rc == 0);
    assert (val == 8192);

    rc = zmq_getsockopt (socket, ZMQ_RCVBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 8192);

    val = 16384;

    rc = zmq_setsockopt (socket, ZMQ_RCVBUF, &val, sizeof (val));
    assert (rc == 0);
    assert (val == 16384);

    rc = zmq_getsockopt (socket, ZMQ_RCVBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 16384);

    zmq_close (socket);
    zmq_ctx_term (ctx);
}

void test_setsockopt_tcp_send_buffer (void)
{
    int rc;
    void *ctx = zmq_ctx_new ();
    void *socket = zmq_socket (ctx, ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    rc = zmq_getsockopt (socket, ZMQ_SNDBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 8192);

    rc = zmq_setsockopt (socket, ZMQ_SNDBUF, &val, sizeof (val));
    assert (rc == 0);
    assert (val == 8192);

    rc = zmq_getsockopt (socket, ZMQ_SNDBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 8192);

    val = 16384;

    rc = zmq_setsockopt (socket, ZMQ_SNDBUF, &val, sizeof (val));
    assert (rc == 0);
    assert (val == 16384);

    rc = zmq_getsockopt (socket, ZMQ_SNDBUF, &val, &placeholder);
    assert (rc == 0);
    assert (val == 16384);

    zmq_close (socket);
    zmq_ctx_term (ctx);
}

void test_setsockopt_use_fd ()
{
    int rc;
    void *ctx = zmq_ctx_new ();
    void *socket = zmq_socket (ctx, ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof (val);

    rc = zmq_getsockopt (socket, ZMQ_USE_FD, &val, &placeholder);
    assert(rc == 0);
    assert(val == -1);

    val = 3;

    rc = zmq_setsockopt (socket, ZMQ_USE_FD, &val, sizeof(val));
    assert(rc == 0);
    assert(val == 3);

    rc = zmq_getsockopt (socket, ZMQ_USE_FD, &val, &placeholder);
    assert(rc == 0);
    assert(val == 3);

    zmq_close (socket);
    zmq_ctx_term (ctx);
}

int main (void)
{
    test_setsockopt_tcp_recv_buffer ();
    test_setsockopt_tcp_send_buffer ();
    test_setsockopt_use_fd ();
}
