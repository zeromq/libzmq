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

#define CONTENT_SIZE 13
#define CONTENT_SIZE_MAX 32
#define ROUTING_ID_SIZE 10
#define ROUTING_ID_SIZE_MAX 32
#define QT_WORKERS 5
#define QT_CLIENTS 3
#define is_verbose 0

struct thread_data
{
    void *ctx;
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


static void client_task (void *db_)
{
    struct thread_data *databag = (struct thread_data *) db_;
    // Endpoint socket gets random port to avoid test failing when port in use
    void *endpoint = zmq_socket (databag->ctx, ZMQ_PAIR);
    assert (endpoint);
    int linger = 0;
    int rc = zmq_setsockopt (endpoint, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    char endpoint_source[256];
    sprintf (endpoint_source, "inproc://endpoint%d", databag->id);
    rc = zmq_connect (endpoint, endpoint_source);
    assert (rc == 0);
    char *my_endpoint = s_recv (endpoint);
    assert (my_endpoint);

    void *client = zmq_socket (databag->ctx, ZMQ_DEALER);
    assert (client);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (databag->ctx, ZMQ_SUB);
    assert (control);
    rc = zmq_setsockopt (control, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);
    rc = zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_connect (control, "inproc://control");
    assert (rc == 0);

    char content[CONTENT_SIZE_MAX];
    // Set random routing id to make tracing easier
    char routing_id[ROUTING_ID_SIZE];
    sprintf (routing_id, "%04X-%04X", rand () % 0xFFFF, rand () % 0xFFFF);
    rc =
      zmq_setsockopt (client, ZMQ_ROUTING_ID, routing_id,
                      ROUTING_ID_SIZE); // includes '\0' as an helper for printf
    assert (rc == 0);
    linger = 0;
    rc = zmq_setsockopt (client, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_connect (client, my_endpoint);
    assert (rc == 0);

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
                rc = zmq_recv (client, content, CONTENT_SIZE_MAX, 0);
                assert (rc == CONTENT_SIZE);
                if (is_verbose)
                    printf (
                      "client receive - routing_id = %s    content = %s\n",
                      routing_id, content);
                //  Check that message is still the same
                assert (memcmp (content, "request #", 9) == 0);
                rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
                assert (rc == 0);
                assert (!rcvmore);
            }
            if (items[1].revents & ZMQ_POLLIN) {
                rc = zmq_recv (control, content, CONTENT_SIZE_MAX, 0);

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

            rc = zmq_send (client, content, CONTENT_SIZE, 0);
            assert (rc == CONTENT_SIZE);
        }
    }

    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);
    rc = zmq_close (endpoint);
    assert (rc == 0);
    free (my_endpoint);
}

// This is our server task.
// It uses the multithreaded server model to deal requests out to a pool
// of workers and route replies back to clients. One worker can handle
// one request at a time but one client can talk to multiple workers at
// once.

static void server_worker (void *ctx_);

void server_task (void *ctx_)
{
    // Frontend socket talks to clients over TCP
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    void *frontend = zmq_socket (ctx_, ZMQ_ROUTER);
    assert (frontend);
    int linger = 0;
    int rc = zmq_setsockopt (frontend, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_bind (frontend, "tcp://127.0.0.1:*");
    assert (rc == 0);
    rc = zmq_getsockopt (frontend, ZMQ_LAST_ENDPOINT, my_endpoint, &len);
    assert (rc == 0);

    // Backend socket talks to workers over inproc
    void *backend = zmq_socket (ctx_, ZMQ_DEALER);
    assert (backend);
    rc = zmq_setsockopt (backend, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_bind (backend, "inproc://backend");
    assert (rc == 0);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx_, ZMQ_REP);
    assert (control);
    rc = zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_connect (control, "inproc://control_proxy");
    assert (rc == 0);

    // Launch pool of worker threads, precise number is not critical
    int thread_nbr;
    void *threads[5];
    for (thread_nbr = 0; thread_nbr < QT_WORKERS; thread_nbr++)
        threads[thread_nbr] = zmq_threadstart (&server_worker, ctx_);

    // Endpoint socket sends random port to avoid test failing when port in use
    void *endpoint_receivers[QT_CLIENTS];
    char endpoint_source[256];
    for (int i = 0; i < QT_CLIENTS; ++i) {
        endpoint_receivers[i] = zmq_socket (ctx_, ZMQ_PAIR);
        assert (endpoint_receivers[i]);
        rc = zmq_setsockopt (endpoint_receivers[i], ZMQ_LINGER, &linger,
                             sizeof (linger));
        assert (rc == 0);
        sprintf (endpoint_source, "inproc://endpoint%d", i);
        rc = zmq_bind (endpoint_receivers[i], endpoint_source);
        assert (rc == 0);
    }

    for (int i = 0; i < QT_CLIENTS; ++i) {
        rc = s_send (endpoint_receivers[i], my_endpoint);
        assert (rc > 0);
    }

    // Connect backend to frontend via a proxy
    rc = zmq_proxy_steerable (frontend, backend, NULL, control);
    assert (rc == 0);

    for (thread_nbr = 0; thread_nbr < QT_WORKERS; thread_nbr++)
        zmq_threadclose (threads[thread_nbr]);

    rc = zmq_close (frontend);
    assert (rc == 0);
    rc = zmq_close (backend);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);
    for (int i = 0; i < QT_CLIENTS; ++i) {
        rc = zmq_close (endpoint_receivers[i]);
        assert (rc == 0);
    }
}

// Each worker task works on one request at a time and sends a random number
// of replies back, with random delays between replies:
// The comments in the first column, if suppressed, makes it a poller version

static void server_worker (void *ctx_)
{
    void *worker = zmq_socket (ctx_, ZMQ_DEALER);
    assert (worker);
    int linger = 0;
    int rc = zmq_setsockopt (worker, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_connect (worker, "inproc://backend");
    assert (rc == 0);

    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx_, ZMQ_SUB);
    assert (control);
    rc = zmq_setsockopt (control, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);
    rc = zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_connect (control, "inproc://control");
    assert (rc == 0);

    char content[CONTENT_SIZE_MAX]; //    bigger than what we need to check that
    char routing_id[ROUTING_ID_SIZE_MAX]; // the size received is the size sent

    bool run = true;
    bool keep_sending = true;
    while (run) {
        rc = zmq_recv (control, content, CONTENT_SIZE_MAX,
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
            assert (rc == CONTENT_SIZE);
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
                    assert (rc == ROUTING_ID_SIZE);
                    rc = zmq_send (worker, content, CONTENT_SIZE, 0);
                    assert (rc == CONTENT_SIZE);
                }
            }
        }
    }
    rc = zmq_close (worker);
    assert (rc == 0);
    rc = zmq_close (control);
    assert (rc == 0);
}

uint64_t recv_stat (void *sock_, bool last_)
{
    uint64_t res;
    zmq_msg_t stats_msg;

    int rc = zmq_msg_init (&stats_msg);
    assert (rc == 0);
    rc = zmq_recvmsg (sock_, &stats_msg, 0);
    assert (rc == sizeof (uint64_t));
    memcpy (&res, zmq_msg_data (&stats_msg), zmq_msg_size (&stats_msg));
    rc = zmq_msg_close (&stats_msg);
    assert (rc == 0);

    int more;
    size_t moresz = sizeof more;
    rc = zmq_getsockopt (sock_, ZMQ_RCVMORE, &more, &moresz);
    assert (rc == 0);
    assert ((last_ && !more) || (!last_ && more));

    return res;
}

// Utility function to interrogate the proxy:

void check_proxy_stats (void *control_proxy_)
{
    zmq_proxy_stats_t total_stats;
    int rc;

    rc = zmq_send (control_proxy_, "STATISTICS", 10, 0);
    assert (rc == 10);

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
    assert (total_stats.frontend.msg_in
            == (unsigned) zmq_atomic_counter_value (g_clients_pkts_out));
    assert (total_stats.frontend.msg_out
            == (unsigned) zmq_atomic_counter_value (g_workers_pkts_out));
    assert (total_stats.backend.msg_in
            == (unsigned) zmq_atomic_counter_value (g_workers_pkts_out));
    assert (total_stats.backend.msg_out
            == (unsigned) zmq_atomic_counter_value (g_clients_pkts_out));
}


// The main thread simply starts several clients and a server, and then
// waits for the server to finish.

int main (void)
{
    setup_test_environment ();

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    g_clients_pkts_out = zmq_atomic_counter_new ();
    g_workers_pkts_out = zmq_atomic_counter_new ();


    // Control socket receives terminate command from main over inproc
    void *control = zmq_socket (ctx, ZMQ_PUB);
    assert (control);
    int linger = 0;
    int rc = zmq_setsockopt (control, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_bind (control, "inproc://control");
    assert (rc == 0);

    // Control socket receives terminate command from main over inproc
    void *control_proxy = zmq_socket (ctx, ZMQ_REQ);
    assert (control_proxy);
    rc = zmq_setsockopt (control_proxy, ZMQ_LINGER, &linger, sizeof (linger));
    assert (rc == 0);
    rc = zmq_bind (control_proxy, "inproc://control_proxy");
    assert (rc == 0);

    void *threads[QT_CLIENTS + 1];
    struct thread_data databags[QT_CLIENTS + 1];
    for (int i = 0; i < QT_CLIENTS; i++) {
        databags[i].ctx = ctx;
        databags[i].id = i;
        threads[i] = zmq_threadstart (&client_task, &databags[i]);
    }
    threads[QT_CLIENTS] = zmq_threadstart (&server_task, ctx);
    msleep (500); // Run for 500 ms then quit


    if (is_verbose)
        printf ("stopping all clients and server workers\n");
    rc = zmq_send (control, "STOP", 4, 0);
    assert (rc == 4);

    msleep (500); // Wait for all clients and workers to STOP


    if (is_verbose)
        printf ("retrieving stats from the proxy\n");
    check_proxy_stats (control_proxy);

    if (is_verbose)
        printf ("shutting down all clients and server workers\n");
    rc = zmq_send (control, "TERMINATE", 9, 0);
    assert (rc == 9);

    if (is_verbose)
        printf ("shutting down the proxy\n");
    rc = zmq_send (control_proxy, "TERMINATE", 9, 0);
    assert (rc == 9);


    rc = zmq_close (control);
    assert (rc == 0);
    rc = zmq_close (control_proxy);
    assert (rc == 0);

    for (int i = 0; i < QT_CLIENTS + 1; i++)
        zmq_threadclose (threads[i]);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
    return 0;
}
