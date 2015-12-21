#include "testutil.hpp"

void test_setsockopt_tcp_recv_buffer()
{
    int rc;
    void *ctx = zmq_ctx_new();
    void *socket = zmq_socket(ctx, ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof(val);

    rc = zmq_getsockopt(socket, ZMQ_TCP_RECV_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 8192);

    rc = zmq_setsockopt(socket, ZMQ_TCP_RECV_BUFFER, &val, sizeof(val));
    assert(rc == 0);
    assert(val == 8192);

    rc = zmq_getsockopt(socket, ZMQ_TCP_RECV_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 8192);

    val = 16384;

    rc = zmq_setsockopt(socket, ZMQ_TCP_RECV_BUFFER, &val, sizeof(val));
    assert(rc == 0);
    assert(val == 16384);

    rc = zmq_getsockopt(socket, ZMQ_TCP_RECV_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 16384);

    zmq_close(socket);
    zmq_ctx_term(ctx);
}

void test_setsockopt_tcp_send_buffer()
{
    int rc;
    void *ctx = zmq_ctx_new();
    void *socket = zmq_socket(ctx, ZMQ_PUSH);

    int val = 0;
    size_t placeholder = sizeof(val);

    rc = zmq_getsockopt(socket, ZMQ_TCP_SEND_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 8192);

    rc = zmq_setsockopt(socket, ZMQ_TCP_SEND_BUFFER, &val, sizeof(val));
    assert(rc == 0);
    assert(val == 8192);

    rc = zmq_getsockopt(socket, ZMQ_TCP_SEND_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 8192);

    val = 16384;

    rc = zmq_setsockopt(socket, ZMQ_TCP_SEND_BUFFER, &val, sizeof(val));
    assert(rc == 0);
    assert(val == 16384);

    rc = zmq_getsockopt(socket, ZMQ_TCP_SEND_BUFFER, &val, &placeholder);
    assert(rc == 0);
    assert(val == 16384);

    zmq_close(socket);
    zmq_ctx_term(ctx);
}


int main()
{
    test_setsockopt_tcp_recv_buffer();
    test_setsockopt_tcp_send_buffer();
}
