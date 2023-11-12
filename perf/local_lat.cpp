/* SPDX-License-Identifier: MPL-2.0 */

#include "../include/zmq.h"
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[])
{
    const char *bind_to;
    int roundtrip_count;
    size_t message_size;
    void *ctx;
    void *s;
    int rc;
    int i;
    zmq_msg_t msg;

    if (argc != 4) {
        printf ("usage: local_lat <bind-to> <message-size> "
                "<roundtrip-count>\n");
        return 1;
    }
    bind_to = argv[1];
    message_size = atoi (argv[2]);
    roundtrip_count = atoi (argv[3]);

    ctx = zmq_init (1);
    if (!ctx) {
        printf ("error in zmq_init: %s\n", zmq_strerror (errno));
        return -1;
    }

    s = zmq_socket (ctx, ZMQ_REP);
    if (!s) {
        printf ("error in zmq_socket: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_bind (s, bind_to);
    if (rc != 0) {
        printf ("error in zmq_bind: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_msg_init (&msg);
    if (rc != 0) {
        printf ("error in zmq_msg_init: %s\n", zmq_strerror (errno));
        return -1;
    }

    for (i = 0; i != roundtrip_count; i++) {
        rc = zmq_recvmsg (s, &msg, 0);
        if (rc < 0) {
            printf ("error in zmq_recvmsg: %s\n", zmq_strerror (errno));
            return -1;
        }
        if (zmq_msg_size (&msg) != message_size) {
            printf ("message of incorrect size received\n");
            return -1;
        }
        rc = zmq_sendmsg (s, &msg, 0);
        if (rc < 0) {
            printf ("error in zmq_sendmsg: %s\n", zmq_strerror (errno));
            return -1;
        }
    }

    rc = zmq_msg_close (&msg);
    if (rc != 0) {
        printf ("error in zmq_msg_close: %s\n", zmq_strerror (errno));
        return -1;
    }

    zmq_sleep (1);

    rc = zmq_close (s);
    if (rc != 0) {
        printf ("error in zmq_close: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_ctx_term (ctx);
    if (rc != 0) {
        printf ("error in zmq_ctx_term: %s\n", zmq_strerror (errno));
        return -1;
    }

    return 0;
}
