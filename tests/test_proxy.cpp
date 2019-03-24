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

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <stdlib.h>
#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

#define CONTENT_SIZE 13
#define CONTENT_SIZE_MAX 32
#define ROUTING_ID_SIZE 10
#define ROUTING_ID_SIZE_MAX 32
#define QT_WORKERS 5
#define QT_CLIENTS 3
#define is_verbose 0

struct thread_data
{
    int id;
};

typedef struct
{
    uint64_t msg_in;
    uint64_t bytes_in;
    uint64_t msg_out;
    uint64_t bytes_out;
} zmq_socket_stats_t;

typedef struct
{
    zmq_socket_stats_t frontend;
    zmq_socket_stats_t backend;
} zmq_proxy_stats_t;

void *g_clients_pkts_out = NULL;
void *g_workers_pkts_out = NULL;

// Asynchronous client-to-server (DEALER to ROUTER) - pure libzmq
//
// While this example runs in a single process, that is to make
// it easier to start and stop the example. Each task may have its own
// context and conceptually acts as a separate process. To have this
// behaviour, it is necessary to replace the inproc transport of the
// control socket by a tcp transport.

// This is our client task
// It connects to the server, and then sends a request once per second
// It collects responses as they arrive, and it prints them out. We will
// run several client tasks in parallel, each with a different random ID.

static void client_task (void *db_)
{
    struct thread_data *databag = (struct thread_data *) db_;
    // Endpoint socket gets random port to avoid test failing when port in use
    void *endpoint = zmq_socket (get_test_context (), ZMQ_PAIR);
    TEST_ASSERT_NOT_NULL (endpoint);
    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (endpoint, ZMQ_LINGER, &linger, sizeof (linger)));
    char endpoint_source[256];
    sprintf (endpoint_source, "inproc://endpoint%d", databag->id);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (endpoint, endpoint_source));
    char *my_endpoint = s_recv (endpoint);
    TEST_ASSERT_NOT_NULL (my_endpoint);

    void *client = zmq_socket (get_test_context (), ZMQ_DEALER);
    TEST_ASSERT_NOT_NULL (client);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (get_test_context (), ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (control, ZMQ_SUBSCRIBE, "", 0));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (control, "inproc://control"));

    char content[CONTENT_SIZE_MAX] = {};
    // Set random routing id to make tracing easier
    char routing_id[ROUTING_ID_SIZE] = {};
    sprintf (routing_id, "%04X-%04X", rand () % 0xFFFF, rand () % 0xFFFF);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      client, ZMQ_ROUTING_ID, routing_id,
      ROUTING_ID_SIZE)); // includes '\0' as an helper for printf
    linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    zmq_pollitem_t items[] = {{client, 0, ZMQ_POLLIN, 0},
                              {control, 0, ZMQ_POLLIN, 0}};
    int request_nbr = 0;
    bool run = true;
    bool keep_sending = true;
    while (run) {
        // Tick once per 200 ms, pulling in arriving messages
        int centitick;
        for (centitick = 0; centitick < 20; centitick++) {
            zmq_poll (items, 2, 10);
            if (items[0].revents & ZMQ_POLLIN) {
                int rcvmore;
                size_t sz = sizeof (rcvmore);
                int rc = TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_recv (client, content, CONTENT_SIZE_MAX, 0));
                TEST_ASSERT_EQUAL_INT (CONTENT_SIZE, rc);
                if (is_verbose)
                    printf (
                      "client receive - routing_id = %s    content = %s\n",
                      routing_id, content);
                //  Check that message is still the same
                TEST_ASSERT_EQUAL_STRING_LEN ("request #", content, 9);
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz));
                TEST_ASSERT_FALSE (rcvmore);
            }
            if (items[1].revents & ZMQ_POLLIN) {
                int rc = zmq_recv (control, content, CONTENT_SIZE_MAX, 0);

                if (rc > 0) {
                    content[rc] = 0; // NULL-terminate the command string
                    if (is_verbose)
                        printf (
                          "client receive - routing_id = %s    command = %s\n",
                          routing_id, content);
                    if (memcmp (content, "TERMINATE", 9) == 0) {
                        run = false;
                        break;
                    }
                    if (memcmp (content, "STOP", 4) == 0) {
                        keep_sending = false;
                        break;
                    }
                }
            }
        }

        if (keep_sending) {
            sprintf (content, "request #%03d", ++request_nbr); // CONTENT_SIZE
            if (is_verbose)
                printf ("client send - routing_id = %s    request #%03d\n",
                        routing_id, request_nbr);
            zmq_atomic_counter_inc (g_clients_pkts_out);

            TEST_ASSERT_EQUAL_INT (CONTENT_SIZE,
                                   zmq_send (client, content, CONTENT_SIZE, 0));
        }
    }

    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (client));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (control));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (endpoint));
    free (my_endpoint);
}

// This is our server task.
// It uses the multithreaded server model to deal requests out to a pool
// of workers and route replies back to clients. One worker can handle
// one request at a time but one client can talk to multiple workers at
// once.

static void server_worker (void * /*unused_*/);

void server_task (void * /*unused_*/)
{
    // Frontend socket talks to clients over TCP
    char my_endpoint[MAX_SOCKET_STRING];
    void *frontend = zmq_socket (get_test_context (), ZMQ_ROUTER);
    TEST_ASSERT_NOT_NULL (frontend);
    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (frontend, ZMQ_LINGER, &linger, sizeof (linger)));
    bind_loopback_ipv4 (frontend, my_endpoint, sizeof my_endpoint);

    // Backend socket talks to workers over inproc
    void *backend = zmq_socket (get_test_context (), ZMQ_DEALER);
    TEST_ASSERT_NOT_NULL (backend);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (backend, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (backend, "inproc://backend"));

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (get_test_context (), ZMQ_REP);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (control, "inproc://control_proxy"));

    // Launch pool of worker threads, precise number is not critical
    int thread_nbr;
    void *threads[5];
    for (thread_nbr = 0; thread_nbr < QT_WORKERS; thread_nbr++)
        threads[thread_nbr] = zmq_threadstart (&server_worker, NULL);

    // Endpoint socket sends random port to avoid test failing when port in use
    void *endpoint_receivers[QT_CLIENTS];
    char endpoint_source[256];
    for (int i = 0; i < QT_CLIENTS; ++i) {
        endpoint_receivers[i] = zmq_socket (get_test_context (), ZMQ_PAIR);
        TEST_ASSERT_NOT_NULL (endpoint_receivers[i]);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          endpoint_receivers[i], ZMQ_LINGER, &linger, sizeof (linger)));
        sprintf (endpoint_source, "inproc://endpoint%d", i);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_bind (endpoint_receivers[i], endpoint_source));
    }

    for (int i = 0; i < QT_CLIENTS; ++i) {
        send_string_expect_success (endpoint_receivers[i], my_endpoint, 0);
    }

    // Connect backend to frontend via a proxy
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_proxy_steerable (frontend, backend, NULL, control));

    for (thread_nbr = 0; thread_nbr < QT_WORKERS; thread_nbr++)
        zmq_threadclose (threads[thread_nbr]);

    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (frontend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (backend));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (control));
    for (int i = 0; i < QT_CLIENTS; ++i) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_close (endpoint_receivers[i]));
    }
}

// Each worker task works on one request at a time and sends a random number
// of replies back, with random delays between replies:
// The comments in the first column, if suppressed, makes it a poller version

static void server_worker (void * /*unused_*/)
{
    void *worker = zmq_socket (get_test_context (), ZMQ_DEALER);
    TEST_ASSERT_NOT_NULL (worker);
    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (worker, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (worker, "inproc://backend"));

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (get_test_context (), ZMQ_SUB);
    TEST_ASSERT_NOT_NULL (control);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (control, ZMQ_SUBSCRIBE, "", 0));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (control, "inproc://control"));

    char content[CONTENT_SIZE_MAX] =
      {}; // bigger than what we need to check that
    char routing_id[ROUTING_ID_SIZE_MAX] =
      {}; // the size received is the size sent

    bool run = true;
    bool keep_sending = true;
    while (run) {
        int rc = zmq_recv (control, content, CONTENT_SIZE_MAX,
                           ZMQ_DONTWAIT); // usually, rc == -1 (no message)
        if (rc > 0) {
            content[rc] = 0; // NULL-terminate the command string
            if (is_verbose)
                printf ("server_worker receives command = %s\n", content);
            if (memcmp (content, "TERMINATE", 9) == 0)
                run = false;
            if (memcmp (content, "STOP", 4) == 0)
                keep_sending = false;
        }
        // The DEALER socket gives us the reply envelope and message
        // if we don't poll, we have to use ZMQ_DONTWAIT, if we poll, we can block-receive with 0
        rc = zmq_recv (worker, routing_id, ROUTING_ID_SIZE_MAX, ZMQ_DONTWAIT);
        if (rc == ROUTING_ID_SIZE) {
            rc = zmq_recv (worker, content, CONTENT_SIZE_MAX, 0);
            TEST_ASSERT_EQUAL_INT (CONTENT_SIZE, rc);
            if (is_verbose)
                printf ("server receive - routing_id = %s    content = %s\n",
                        routing_id, content);

            // Send 0..4 replies back
            if (keep_sending) {
                int reply, replies = rand () % 5;
                for (reply = 0; reply < replies; reply++) {
                    // Sleep for some fraction of a second
                    msleep (rand () % 10 + 1);

                    //  Send message from server to client
                    if (is_verbose)
                        printf ("server send - routing_id = %s    reply\n",
                                routing_id);
                    zmq_atomic_counter_inc (g_workers_pkts_out);

                    rc = zmq_send (worker, routing_id, ROUTING_ID_SIZE,
                                   ZMQ_SNDMORE);
                    TEST_ASSERT_EQUAL_INT (ROUTING_ID_SIZE, rc);
                    rc = zmq_send (worker, content, CONTENT_SIZE, 0);
                    TEST_ASSERT_EQUAL_INT (CONTENT_SIZE, rc);
                }
            }
        }
    }
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (worker));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (control));
}

uint64_t recv_stat (void *sock_, bool last_)
{
    uint64_t res;
    zmq_msg_t stats_msg;

    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&stats_msg));
    TEST_ASSERT_EQUAL_INT (sizeof (uint64_t),
                           zmq_recvmsg (sock_, &stats_msg, 0));
    memcpy (&res, zmq_msg_data (&stats_msg), zmq_msg_size (&stats_msg));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&stats_msg));

    int more;
    size_t moresz = sizeof more;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sock_, ZMQ_RCVMORE, &more, &moresz));
    TEST_ASSERT_TRUE ((last_ && !more) || (!last_ && more));

    return res;
}

// Utility function to interrogate the proxy:

void check_proxy_stats (void *control_proxy_)
{
    zmq_proxy_stats_t total_stats;

    send_string_expect_success (control_proxy_, "STATISTICS", 0);

    // first frame of the reply contains FRONTEND stats:
    total_stats.frontend.msg_in = recv_stat (control_proxy_, false);
    total_stats.frontend.bytes_in = recv_stat (control_proxy_, false);
    total_stats.frontend.msg_out = recv_stat (control_proxy_, false);
    total_stats.frontend.bytes_out = recv_stat (control_proxy_, false);

    // second frame of the reply contains BACKEND stats:
    total_stats.backend.msg_in = recv_stat (control_proxy_, false);
    total_stats.backend.bytes_in = recv_stat (control_proxy_, false);
    total_stats.backend.msg_out = recv_stat (control_proxy_, false);
    total_stats.backend.bytes_out = recv_stat (control_proxy_, true);

    // check stats

    if (is_verbose) {
        printf (
          "frontend: pkts_in=%lu bytes_in=%lu  pkts_out=%lu bytes_out=%lu\n",
          (unsigned long int) total_stats.frontend.msg_in,
          (unsigned long int) total_stats.frontend.bytes_in,
          (unsigned long int) total_stats.frontend.msg_out,
          (unsigned long int) total_stats.frontend.bytes_out);
        printf (
          "backend: pkts_in=%lu bytes_in=%lu  pkts_out=%lu bytes_out=%lu\n",
          (unsigned long int) total_stats.backend.msg_in,
          (unsigned long int) total_stats.backend.bytes_in,
          (unsigned long int) total_stats.backend.msg_out,
          (unsigned long int) total_stats.backend.bytes_out);

        printf ("clients sent out %d requests\n",
                zmq_atomic_counter_value (g_clients_pkts_out));
        printf ("workers sent out %d replies\n",
                zmq_atomic_counter_value (g_workers_pkts_out));
    }
    TEST_ASSERT_EQUAL_UINT (
      (unsigned) zmq_atomic_counter_value (g_clients_pkts_out),
      total_stats.frontend.msg_in);
    TEST_ASSERT_EQUAL_UINT (
      (unsigned) zmq_atomic_counter_value (g_workers_pkts_out),
      total_stats.frontend.msg_out);
    TEST_ASSERT_EQUAL_UINT (
      (unsigned) zmq_atomic_counter_value (g_workers_pkts_out),
      total_stats.backend.msg_in);
    TEST_ASSERT_EQUAL_UINT (
      (unsigned) zmq_atomic_counter_value (g_clients_pkts_out),
      total_stats.backend.msg_out);
}


// The main thread simply starts several clients and a server, and then
// waits for the server to finish.

void test_proxy ()
{
    g_clients_pkts_out = zmq_atomic_counter_new ();
    g_workers_pkts_out = zmq_atomic_counter_new ();

    // Control socket receives terminate command from main over inproc
    void *control = test_context_socket (ZMQ_PUB);
    int linger = 0;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (control, "inproc://control"));

    // Control socket receives terminate command from main over inproc
    void *control_proxy = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (control_proxy, ZMQ_LINGER, &linger, sizeof (linger)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (control_proxy, "inproc://control_proxy"));

    void *threads[QT_CLIENTS + 1];
    struct thread_data databags[QT_CLIENTS + 1];
    for (int i = 0; i < QT_CLIENTS; i++) {
        databags[i].id = i;
        threads[i] = zmq_threadstart (&client_task, &databags[i]);
    }
    threads[QT_CLIENTS] = zmq_threadstart (&server_task, NULL);
    msleep (500); // Run for 500 ms then quit

    if (is_verbose)
        printf ("stopping all clients and server workers\n");
    send_string_expect_success (control, "STOP", 0);

    msleep (500); // Wait for all clients and workers to STOP

    if (is_verbose)
        printf ("retrieving stats from the proxy\n");
    check_proxy_stats (control_proxy);

    if (is_verbose)
        printf ("shutting down all clients and server workers\n");
    send_string_expect_success (control, "TERMINATE", 0);

    if (is_verbose)
        printf ("shutting down the proxy\n");
    send_string_expect_success (control_proxy, "TERMINATE", 0);

    test_context_socket_close (control);
    test_context_socket_close (control_proxy);

    for (int i = 0; i < QT_CLIENTS + 1; i++)
        zmq_threadclose (threads[i]);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_proxy);
    return UNITY_END ();
}
