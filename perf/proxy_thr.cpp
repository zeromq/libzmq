/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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
#include "../include/zmq.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <string>

#include "platform.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif


/*
   Asynchronous proxy benchmark using ZMQ_XPUB_NODROP.

   Topology:

     XPUB                      SUB
      |                         |
      +-----> XSUB -> XPUB -----/
      |       ^^^^^^^^^^^^
     XPUB      ZMQ proxy

   All connections use "inproc" transport. The two XPUB sockets start
   flooding the proxy. The throughput is computed using the bytes received
   in the SUB socket.
*/


#define HWM 10000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof (x) / sizeof (*x))
#endif

#define TEST_ASSERT_SUCCESS_ERRNO(expr)                                        \
    test_assert_success_message_errno_helper (expr, NULL, #expr)


static uint64_t message_count = 0;
static size_t message_size = 0;


typedef struct
{
    void *context;
    int thread_idx;
    const char *frontend_endpoint[4];
    const char *backend_endpoint[4];
    const char *control_endpoint;
} proxy_hwm_cfg_t;


int test_assert_success_message_errno_helper (int rc_,
                                              const char *msg_,
                                              const char *expr_)
{
    if (rc_ == -1) {
        char buffer[512];
        buffer[sizeof (buffer) - 1] =
          0; //  to ensure defined behavior with VC++ <= 2013
        printf ("%s failed%s%s%s, errno = %i (%s)", expr_,
                msg_ ? " (additional info: " : "", msg_ ? msg_ : "",
                msg_ ? ")" : "", zmq_errno (), zmq_strerror (zmq_errno ()));
        exit (1);
    }
    return rc_;
}

static void set_hwm (void *skt)
{
    int hwm = HWM;

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (skt, ZMQ_SNDHWM, &hwm, sizeof (hwm)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (skt, ZMQ_RCVHWM, &hwm, sizeof (hwm)));
}

static void publisher_thread_main (void *pvoid)
{
    const proxy_hwm_cfg_t *cfg = (proxy_hwm_cfg_t *) pvoid;
    const int idx = cfg->thread_idx;
    int optval;
    int rc;

    void *pubsocket = zmq_socket (cfg->context, ZMQ_XPUB);
    assert (pubsocket);

    set_hwm (pubsocket);

    optval = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pubsocket, ZMQ_XPUB_NODROP, &optval, sizeof (optval)));

    optval = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pubsocket, ZMQ_SNDTIMEO, &optval, sizeof (optval)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (pubsocket, cfg->frontend_endpoint[idx]));

    //  Wait before starting TX operations till 1 subscriber has subscribed
    //  (in this test there's 1 subscriber only)
    char buffer[32] = {};
    rc = TEST_ASSERT_SUCCESS_ERRNO (
      zmq_recv (pubsocket, buffer, sizeof (buffer), 0));
    if (rc != 1) {
        printf ("invalid response length: expected 1, received %d", rc);
        exit (1);
    }
    if (buffer[0] != 1) {
        printf ("invalid response value: expected 1, received %d",
                (int) buffer[0]);
        exit (1);
    }

    zmq_msg_t msg_orig;
    rc = zmq_msg_init_size (&msg_orig, message_size);
    assert (rc == 0);
    memset (zmq_msg_data (&msg_orig), 'A', zmq_msg_size (&msg_orig));

    uint64_t send_count = 0;
    while (send_count < message_count) {
        zmq_msg_t msg;
        zmq_msg_init (&msg);
        rc = zmq_msg_copy (&msg, &msg_orig);
        assert (rc == 0);

        //  Send the message to the socket
        rc = zmq_msg_send (&msg, pubsocket, 0);
        if (rc != -1) {
            send_count++;
        } else {
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
        }
    }

    zmq_close (pubsocket);
    //printf ("publisher thread ended\n");
}

static void subscriber_thread_main (void *pvoid)
{
    const proxy_hwm_cfg_t *cfg = (proxy_hwm_cfg_t *) pvoid;
    const int idx = cfg->thread_idx;

    void *subsocket = zmq_socket (cfg->context, ZMQ_SUB);
    assert (subsocket);

    set_hwm (subsocket);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (subsocket, ZMQ_SUBSCRIBE, 0, 0));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (subsocket, cfg->backend_endpoint[idx]));

    //  Receive message_count messages
    uint64_t rxsuccess = 0;
    bool success = true;
    while (success) {
        zmq_msg_t msg;
        int rc = zmq_msg_init (&msg);
        assert (rc == 0);

        rc = zmq_msg_recv (&msg, subsocket, 0);
        if (rc != -1) {
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
            rxsuccess++;
        }

        if (rxsuccess == message_count)
            break;
    }

    //  Cleanup

    zmq_close (subsocket);
    //printf ("subscriber thread ended\n");
}

static void proxy_thread_main (void *pvoid)
{
    const proxy_hwm_cfg_t *cfg = (proxy_hwm_cfg_t *) pvoid;
    int rc;

    //  FRONTEND SUB

    void *frontend_xsub = zmq_socket (
      cfg->context,
      ZMQ_XSUB); // the frontend is the one exposed to internal threads (INPROC)
    assert (frontend_xsub);

    set_hwm (frontend_xsub);

    //  Bind FRONTEND
    for (unsigned int i = 0; i < ARRAY_SIZE (cfg->frontend_endpoint); i++) {
        const char *ep = cfg->frontend_endpoint[i];
        if (ep != NULL) {
            assert (strlen (ep) > 5);
            rc = zmq_bind (frontend_xsub, ep);
            assert (rc == 0);
        }
    }

    //  BACKEND PUB

    void *backend_xpub = zmq_socket (
      cfg->context,
      ZMQ_XPUB); //  the backend is the one exposed to the external world (TCP)
    assert (backend_xpub);

    int optval = 1;
    rc =
      zmq_setsockopt (backend_xpub, ZMQ_XPUB_NODROP, &optval, sizeof (optval));
    assert (rc == 0);

    set_hwm (backend_xpub);

    //  Bind BACKEND
    for (unsigned int i = 0; i < ARRAY_SIZE (cfg->backend_endpoint); i++) {
        const char *ep = cfg->backend_endpoint[i];
        if (ep != NULL) {
            assert (strlen (ep) > 5);
            rc = zmq_bind (backend_xpub, ep);
            assert (rc == 0);
        }
    }

    //  CONTROL REP

    void *control_rep = zmq_socket (
      cfg->context,
      ZMQ_REP); //  This one is used by the proxy to receive&reply to commands
    assert (control_rep);

    //  Bind CONTROL
    rc = zmq_bind (control_rep, cfg->control_endpoint);
    assert (rc == 0);

    //  Start proxying!

    zmq_proxy_steerable (frontend_xsub, backend_xpub, NULL, control_rep);

    zmq_close (frontend_xsub);
    zmq_close (backend_xpub);
    zmq_close (control_rep);
    //printf ("proxy thread ended\n");
}

void terminate_proxy (const proxy_hwm_cfg_t *cfg)
{
    //  CONTROL REQ

    void *control_req = zmq_socket (
      cfg->context,
      ZMQ_REQ); //  This one can be used to send command to the proxy
    assert (control_req);

    //  Connect CONTROL-REQ: a socket to which send commands
    int rc = zmq_connect (control_req, cfg->control_endpoint);
    assert (rc == 0);

    //  Ask the proxy to exit: the subscriber has received all messages

    rc = zmq_send (control_req, "TERMINATE", 9, 0);
    assert (rc == 9);

    zmq_close (control_req);
}

//  The main thread simply starts some publishers, a proxy,
//  and a subscriber. Finish when all packets are received.

int main (int argc, char *argv[])
{
    if (argc != 3) {
        printf ("usage: proxy_thr <message-size> <message-count>\n");
        return 1;
    }

    message_size = atoi (argv[1]);
    message_count = atoi (argv[2]);
    printf ("message size: %d [B]\n", (int) message_size);
    printf ("message count: %d\n", (int) message_count);

    void *context = zmq_ctx_new ();
    assert (context);

    int rv = zmq_ctx_set (context, ZMQ_IO_THREADS, 4);
    assert (rv == 0);

    //  START ALL SECONDARY THREADS

    const char *pub1 = "inproc://perf_pub1";
    const char *pub2 = "inproc://perf_pub2";
    const char *sub1 = "inproc://perf_backend";

    proxy_hwm_cfg_t cfg_global = {};
    cfg_global.context = context;
    cfg_global.frontend_endpoint[0] = pub1;
    cfg_global.frontend_endpoint[1] = pub2;
    cfg_global.backend_endpoint[0] = sub1;
    cfg_global.control_endpoint = "inproc://ctrl";

    //  Proxy
    proxy_hwm_cfg_t cfg_proxy = cfg_global;
    void *proxy = zmq_threadstart (&proxy_thread_main, (void *) &cfg_proxy);
    assert (proxy != 0);

    //  Subscriber 1
    proxy_hwm_cfg_t cfg_sub1 = cfg_global;
    cfg_sub1.thread_idx = 0;
    void *subscriber =
      zmq_threadstart (&subscriber_thread_main, (void *) &cfg_sub1);
    assert (subscriber != 0);

    //  Start measuring
    void *watch = zmq_stopwatch_start ();

    //  Publisher 1
    proxy_hwm_cfg_t cfg_pub1 = cfg_global;
    cfg_pub1.thread_idx = 0;
    void *publisher1 =
      zmq_threadstart (&publisher_thread_main, (void *) &cfg_pub1);
    assert (publisher1 != 0);

    //  Publisher 2
    proxy_hwm_cfg_t cfg_pub2 = cfg_global;
    cfg_pub2.thread_idx = 1;
    void *publisher2 =
      zmq_threadstart (&publisher_thread_main, (void *) &cfg_pub2);
    assert (publisher2 != 0);

    //  Wait for all packets to be received
    zmq_threadclose (subscriber);

    //  Stop measuring
    unsigned long elapsed = zmq_stopwatch_stop (watch);
    if (elapsed == 0)
        elapsed = 1;

    unsigned long throughput =
      (unsigned long) ((double) message_count / (double) elapsed * 1000000);
    double megabits = (double) (throughput * message_size * 8) / 1000000;

    printf ("mean throughput: %d [msg/s]\n", (int) throughput);
    printf ("mean throughput: %.3f [Mb/s]\n", (double) megabits);

    //  Wait for the end of publishers...
    zmq_threadclose (publisher1);
    zmq_threadclose (publisher2);

    //  ... then close the proxy
    terminate_proxy (&cfg_proxy);
    zmq_threadclose (proxy);

    int rc = zmq_ctx_term (context);
    assert (rc == 0);

    return 0;
}
