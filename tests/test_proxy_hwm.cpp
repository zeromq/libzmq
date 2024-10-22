/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"
#include <string.h>
#include <unity.h>
#include <assert.h>
#include <unistd.h>

//
// Asynchronous proxy test using ZMQ_XPUB_NODROP and HWM:
//
// Topology:
//
//   XPUB                      SUB
//    |                         |
//    \-----> XSUB -> XPUB -----/
//           ^^^^^^^^^^^^^^
//             ZMQ proxy
//
// All connections use "inproc" transport and have artificially-low HWMs set.
// Then the PUB socket starts flooding the Proxy. The SUB is artificially slow
// at receiving messages.
// This scenario simulates what happens when a SUB is slower than
// its (X)PUB: since ZMQ_XPUB_NODROP=1, the XPUB will block and then
// also the (X)PUB socket will block.
// The exact number of the messages that go through before (X)PUB blocks depends
// on ZeroMQ internals and how the OS will schedule the different threads.
// In the meanwhile asking statistics to the Proxy must NOT be blocking.
//


#define HWM 10
#define NUM_BYTES_PER_MSG 50000


typedef struct
{
    void *context;
    const char *frontend_endpoint;
    const char *backend_endpoint;
    const char *control_endpoint;

    void *subscriber_received_all;
} proxy_hwm_cfg_t;

static void lower_hwm (void *skt_)
{
    int send_hwm = HWM;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (skt_, ZMQ_SNDHWM, &send_hwm, sizeof (send_hwm)));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (skt_, ZMQ_RCVHWM, &send_hwm, sizeof (send_hwm)));
}

static void publisher_thread_main (void *pvoid_)
{
    const proxy_hwm_cfg_t *const cfg =
      static_cast<const proxy_hwm_cfg_t *> (pvoid_);

    void *pubsocket = zmq_socket (cfg->context, ZMQ_XPUB);
    assert (pubsocket);

    lower_hwm (pubsocket);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pubsocket, cfg->frontend_endpoint));

    int optval = 1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (pubsocket, ZMQ_XPUB_NODROP, &optval, sizeof (optval)));

    // Wait before starting TX operations till 1 subscriber has subscribed
    // (in this test there's 1 subscriber only)
    const char subscription_to_all_topics[] = {1, 0};
    recv_string_expect_success (pubsocket, subscription_to_all_topics, 0);

    uint64_t send_count = 0;
    while (true) {
        zmq_msg_t msg;
        int rc = zmq_msg_init_size (&msg, NUM_BYTES_PER_MSG);
        assert (rc == 0);

        /* Fill in message content with 'AAAAAA' */
        memset (zmq_msg_data (&msg), 'A', NUM_BYTES_PER_MSG);

        /* Send the message to the socket */
        rc = zmq_msg_send (&msg, pubsocket, ZMQ_DONTWAIT);
        if (rc != -1) {
            send_count++;
        } else {
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
            break;
        }
    }

    // VERIFY EXPECTED RESULTS
    // EXPLANATION FOR TX TO BE CONSIDERED SUCCESSFUL:
    // this test has 3 threads doing I/O across 2 queues. Depending on the scheduling,
    // it might happen that 20, 30 or 40 messages go through before the pub blocks.
    // That's because the receiver thread gets kicked once every (hwm_ + 1) / 2 sent
    // messages (search for zeromq sources compute_lwm function).
    // So depending on the scheduling of the second thread, the publisher might get one,
    // two or three more batches in. The ceiling is 40 as there's 2 queues.
    //
    assert (4 * HWM >= send_count && 2 * HWM <= send_count);

    // CLEANUP

    zmq_close (pubsocket);
}

static void subscriber_thread_main (void *pvoid_)
{
    const proxy_hwm_cfg_t *const cfg =
      static_cast<const proxy_hwm_cfg_t *> (pvoid_);

    void *subsocket = zmq_socket (cfg->context, ZMQ_SUB);
    assert (subsocket);

    lower_hwm (subsocket);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (subsocket, ZMQ_SUBSCRIBE, 0, 0));

    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subsocket, cfg->backend_endpoint));


    // receive all sent messages
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

            // after receiving 1st message, set a finite timeout (default is infinite)
            int timeout_ms = 100;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
              subsocket, ZMQ_RCVTIMEO, &timeout_ms, sizeof (timeout_ms)));
        } else {
            break;
        }

        msleep (100);
    }


    // VERIFY EXPECTED RESULTS
    // EXPLANATION FOR RX TO BE CONSIDERED SUCCESSFUL:
    // see publisher thread why we have 3 possible outcomes as number of RX messages

    assert (4 * HWM >= rxsuccess && 2 * HWM <= rxsuccess);

    // INFORM THAT WE COMPLETED:

    zmq_atomic_counter_inc (cfg->subscriber_received_all);

    // CLEANUP

    zmq_close (subsocket);
}

static void proxy_stats_asker_thread_main (void *pvoid_)
{
    const proxy_hwm_cfg_t *const cfg =
      static_cast<const proxy_hwm_cfg_t *> (pvoid_);

    // CONTROL REQ

    void *control_req =
      zmq_socket (cfg->context,
                  ZMQ_REQ); // this one can be used to send command to the proxy
    assert (control_req);

    // connect CONTROL-REQ: a socket to which send commands
    int rc = zmq_connect (control_req, cfg->control_endpoint);
    assert (rc == 0);


    // IMPORTANT: by setting the tx/rx timeouts, we avoid getting blocked when interrogating a proxy which is
    //            itself blocked in a zmq_msg_send() on its XPUB socket having ZMQ_XPUB_NODROP=1!

    int optval = 10;
    rc = zmq_setsockopt (control_req, ZMQ_SNDTIMEO, &optval, sizeof (optval));
    assert (rc == 0);
    rc = zmq_setsockopt (control_req, ZMQ_RCVTIMEO, &optval, sizeof (optval));
    assert (rc == 0);

    optval = 10;
    rc =
      zmq_setsockopt (control_req, ZMQ_REQ_CORRELATE, &optval, sizeof (optval));
    assert (rc == 0);

    rc =
      zmq_setsockopt (control_req, ZMQ_REQ_RELAXED, &optval, sizeof (optval));
    assert (rc == 0);


    // Start!

    while (!zmq_atomic_counter_value (cfg->subscriber_received_all)) {
        usleep (1000); // 1ms -> in best case we will get 1000updates/second
    }

    zmq_close (control_req);
}

static void proxy_thread_main (void *pvoid_)
{
    const proxy_hwm_cfg_t *const cfg =
      static_cast<const proxy_hwm_cfg_t *> (pvoid_);
    int rc;

    // FRONTEND SUB

    void *frontend_xsub = zmq_socket (
      cfg->context,
      ZMQ_XSUB); // the frontend is the one exposed to internal threads (INPROC)
    assert (frontend_xsub);

    lower_hwm (frontend_xsub);

    // bind FRONTEND
    rc = zmq_bind (frontend_xsub, cfg->frontend_endpoint);
    assert (rc == 0);


    // BACKEND PUB

    void *backend_xpub = zmq_socket (
      cfg->context,
      ZMQ_XPUB); // the backend is the one exposed to the external world (TCP)
    assert (backend_xpub);

    int optval = 1;
    rc =
      zmq_setsockopt (backend_xpub, ZMQ_XPUB_NODROP, &optval, sizeof (optval));
    assert (rc == 0);

    lower_hwm (backend_xpub);

    // bind BACKEND
    rc = zmq_bind (backend_xpub, cfg->backend_endpoint);
    assert (rc == 0);


    // CONTROL REP

    void *control_rep = zmq_socket (
      cfg->context,
      ZMQ_REP); // this one is used by the proxy to receive&reply to commands
    assert (control_rep);

    // bind CONTROL
    rc = zmq_bind (control_rep, cfg->control_endpoint);
    assert (rc == 0);


    // start proxying!

    zmq_proxy (frontend_xsub, backend_xpub, NULL);

    zmq_close (frontend_xsub);
    zmq_close (backend_xpub);
    zmq_close (control_rep);
}


// The main thread simply starts several clients and a server, and then
// waits for the server to finish.

int main (void)
{
    setup_test_environment ();

    void *context = zmq_ctx_new ();
    assert (context);


    // START ALL SECONDARY THREADS

    proxy_hwm_cfg_t cfg;
    cfg.context = context;
    cfg.frontend_endpoint = "inproc://frontend";
    cfg.backend_endpoint = "inproc://backend";
    cfg.control_endpoint = "inproc://ctrl";
    cfg.subscriber_received_all = zmq_atomic_counter_new ();

    void *proxy = zmq_threadstart (&proxy_thread_main, (void *) &cfg);
    assert (proxy != 0);
    void *publisher = zmq_threadstart (&publisher_thread_main, (void *) &cfg);
    assert (publisher != 0);
    void *subscriber = zmq_threadstart (&subscriber_thread_main, (void *) &cfg);
    assert (subscriber != 0);
    void *asker =
      zmq_threadstart (&proxy_stats_asker_thread_main, (void *) &cfg);
    assert (asker != 0);


    // CLEANUP

    zmq_threadclose (publisher);
    zmq_threadclose (subscriber);
    zmq_threadclose (asker);

    int rc = zmq_ctx_term (context);
    assert (rc == 0);

    zmq_threadclose (proxy);

    zmq_atomic_counter_destroy (&cfg.subscriber_received_all);

    return 0;
}
