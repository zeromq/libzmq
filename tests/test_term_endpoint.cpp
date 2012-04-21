#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "../include/zmq.h"
#include "../include/zmq_utils.h"


int main (int argc, char *argv [])
{
    int rc;
    char buf[32];
    const char *ep = "tcp://127.0.0.1:5560";

    fprintf (stderr, "unbind endpoint test running...\n");

    //  Create infrastructure.
    void *ctx = zmq_init (1);
    assert (ctx);
    void *push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_bind (push, ep);
    assert (rc == 0);
    void *pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_connect (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established.
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    // Unbind the lisnening endpoint
    rc = zmq_unbind (push, ep);
    assert (rc == 0);

    // Let events some time
    zmq_sleep (1);

    //  Check that sending would block (there's no outbound connection).
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up.
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);


    //  Now the other way round.
    fprintf (stderr, "disconnect endpoint test running...\n");


    //  Create infrastructure.
    ctx = zmq_init (1);
    assert (ctx);
    push = zmq_socket (ctx, ZMQ_PUSH);
    assert (push);
    rc = zmq_connect (push, ep);
    assert (rc == 0);
    pull = zmq_socket (ctx, ZMQ_PULL);
    assert (pull);
    rc = zmq_bind (pull, ep);
    assert (rc == 0);

    //  Pass one message through to ensure the connection is established.
    rc = zmq_send (push, "ABC", 3, 0);
    assert (rc == 3);
    rc = zmq_recv (pull, buf, sizeof (buf), 0);
    assert (rc == 3);

    // Disconnect the bound endpoint
    rc = zmq_disconnect (push, ep);
    assert (rc == 0);

    // Let events some time
    zmq_sleep (1);

    //  Check that sending would block (there's no inbound connections).
    rc = zmq_send (push, "ABC", 3, ZMQ_DONTWAIT);
    assert (rc == -1 && zmq_errno () == EAGAIN);

    //  Clean up.
    rc = zmq_close (pull);
    assert (rc == 0);
    rc = zmq_close (push);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0;
}
