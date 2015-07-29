#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <netinet/in.h>
#include <unistd.h>

#include <zmq.h>

int main()
{
    const int msgsize = 8193;
    char sndbuf[msgsize] = "\xde\xad\xbe\xef";
    unsigned char rcvbuf[msgsize];

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(server_sock!=-1);
    int enable = 1;
    int rc = setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
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
}

