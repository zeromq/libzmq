/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"
#include "../include/zmq_utils.h"

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
#define ID_SIZE 10
#define ID_SIZE_MAX 32
#define QT_REQUESTS 3
#define QT_THREADS 10
#define is_verbose 0

typedef struct config_t {
    void *ctx;
    int index;
} config_t;

int count[QT_THREADS];

void
do_some_stuff (void* config)
{
    config_t* c = (config_t*) config;
    void* ctx = c->ctx;
    int index = c->index;
    free (c);
    assert(index < 100);

    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    // Set random identity to make tracing easier
    char identity [ID_SIZE];
    sprintf (identity, "%04X-%04X", rand() % 0xFFFF, rand() % 0xFFFF);
    int rc = zmq_setsockopt (client, ZMQ_IDENTITY, identity, ID_SIZE); // includes '\0' as an helper for printf
    assert (rc == 0);
    char client_addr[CONTENT_SIZE_MAX];
    sprintf(client_addr, "tcp://127.0.0.1:%04d", 9999 - index); // "tcp://127.0.0.1:9999"
    rc = zmq_connect (client, client_addr);
    assert (rc == 0);

    // Frontend socket talks to clients over TCP
    void *frontend = zmq_socket (ctx, ZMQ_ROUTER);
    assert (frontend);
    rc = zmq_bind (frontend, client_addr);
    assert (rc == 0);

    // Intermediate 1
    void *intermediate1 = zmq_socket (ctx, ZMQ_DEALER);
    assert (intermediate1);
    char middle_addr[CONTENT_SIZE_MAX];
    sprintf(middle_addr, "inproc://intermediate%02d", index); // "inproc://intermediate00"
    rc = zmq_connect (intermediate1, middle_addr);
    assert (rc == 0);

    // Intermediate 2
    void *intermediate2 = zmq_socket (ctx, ZMQ_DEALER);
    assert (intermediate2);
    rc = zmq_bind (intermediate2, middle_addr);
    assert (rc == 0);

    // Backend socket talks to workers over inproc
    void *backend = zmq_socket (ctx, ZMQ_DEALER);
    assert (backend);
    char backend_addr[CONTENT_SIZE_MAX];
    sprintf(backend_addr, "inproc://backend%02d", index); // "inproc://backend00"
    rc = zmq_bind (backend, backend_addr);
    assert (rc == 0);

    void *worker = zmq_socket (ctx, ZMQ_DEALER);
    assert (worker);
//    int linger_time = 100;
//    rc = zmq_setsockopt (worker, ZMQ_LINGER, &linger_time, sizeof(linger_time));
//    assert (rc == 0);
    rc = zmq_connect (worker, backend_addr);
    assert (rc == 0);

    void* open_endpoints[] = {client, worker, NULL};
    void* frontends[] = {frontend,      intermediate2, NULL, NULL, NULL}; // the two last NULL are not necessary, it's just to have an appropriate
    void* backends[] =  {intermediate1, backend,       NULL, NULL, NULL}; // array size to show other possible configurations (cf below)
    int client_socket_pos = 1; // first socket is n° 1. The order is open_endpoints[0], open_endpoints[1], ..., open_endpoints[n],
    int worker_socket_pos = 2; // frontends[0], backends[0], frontends[1], backends[1], etc. NULL sockets are not counted

    switch (index) { // this is just to demonstrate how to use open_endpoints, frontends, backends (results are the same)
    case 1:  client_socket_pos = 2; worker_socket_pos = 1; // inverse client and worker order (this is just a poll order, just the return index is different)
        open_endpoints[0] = worker;   open_endpoints[1] = client;     open_endpoints[2] = NULL;
        frontends[0] = frontend;      frontends[1] = intermediate2;   frontends[2] = NULL;
        backends[0] =  intermediate1; backends[1] =  backend;         backends[2] =  NULL;
        break;
    case 2: client_socket_pos = 1; worker_socket_pos = 6; // open_endpoints is not mandatory, we could just pass NULL to zmq_proxy_open_chain 1st argument
        open_endpoints[0] = NULL;
        frontends[0] = client;    frontends[1] = frontend;      frontends[2] = intermediate2;   frontends[3] = NULL;   frontends[4] = NULL;
        backends[0] =  NULL;      backends[1] =  intermediate1; backends[2] =  backend;         backends[3] =  worker; backends[4] =  NULL;
        break;
    case 3: client_socket_pos = 1; worker_socket_pos = 6; // when an end-point is put in the frontends or backends arrays, it can be put indifferently in one or the other
        open_endpoints[0] = NULL;
        frontends[0] = NULL;      frontends[1] = frontend;      frontends[2] = intermediate2;   frontends[3] = NULL;   frontends[4] = NULL;
        backends[0] =  client;    backends[1] =  intermediate1; backends[2] =  backend;         backends[3] =  worker; backends[4] =  NULL;
        break;
    case 4: client_socket_pos = 1; worker_socket_pos = 6; // when an end-point is put in the frontends or backends arrays, it can be put indifferently in one or the other
        open_endpoints[0] = NULL;
        frontends[0] = NULL;      frontends[1] = frontend;      frontends[2] = intermediate2;   frontends[3] = worker; frontends[4] = NULL;
        backends[0] =  client;    backends[1] =  intermediate1; backends[2] =  backend;         backends[3] =  NULL;   backends[4] =  NULL;
        break;
    case 5: client_socket_pos = 1; worker_socket_pos = 6; // when an end-point is put in the frontends or backends arrays, it can be put indifferently in one or the other
        open_endpoints[0] = NULL;
        frontends[0] = client;    frontends[1] = frontend;      frontends[2] = intermediate2;   frontends[3] = worker; frontends[4] = NULL;
        backends[0] =  NULL;      backends[1] =  intermediate1; backends[2] =  backend;         backends[3] =  NULL;   backends[4] =  NULL;
        break;
    default: // cf default initialisation at the declaration
        break;
    }

    char content [CONTENT_SIZE_MAX];

    if (is_verbose)
        printf ("Thread %2d ready with addresses: \n%s, %s, %s\n", index, client_addr, middle_addr, backend_addr);

    for (int round_ = 0; round_ < 2; round_++) { // test zmq_proxy_open_chain reinitialisation
        for (int request_nbr = 0; request_nbr <= QT_REQUESTS;) { // we ear one more time than the number of request
            // Tick once per 200 ms, pulling in arriving messages
            int centitick;
            for (centitick = 0; centitick < 20; centitick++) {
                // Connect backend to frontend via a proxies
                int trigged_socket = zmq_proxy_open_chain (open_endpoints, frontends, backends, NULL, NULL, NULL, 10);
                if (trigged_socket == -1)
                    break; // terminate the test cleanly: zmq_proxy_open_chain cannot be used because LTS is missing, so it just return -1
                if (trigged_socket == client_socket_pos) {
                    int rcvmore;
                    size_t sz = sizeof (rcvmore);
                    rc = zmq_recv (client, content, CONTENT_SIZE_MAX, 0);
                    assert (rc == CONTENT_SIZE);
                    if (is_verbose) printf("client receive - identity = %s    content = %s\n", identity, content);
                    //  Check that message is still the same
                    assert (memcmp (content, "request #", 9) == 0);
                    rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
                    assert (rc == 0);
                    assert (!rcvmore);
                    count[index]++;
                }
                if (trigged_socket == worker_socket_pos) {
                    // The DEALER socket gives us the reply envelope and message
                    rc = zmq_recv (worker, identity, ID_SIZE_MAX, 0); // ZMQ_DONTWAIT
                    if (rc == ID_SIZE) {
                        rc = zmq_recv (worker, content, CONTENT_SIZE_MAX, 0);
                        assert (rc == CONTENT_SIZE);
                        if (is_verbose)
                            printf ("server receive - identity = %s    content = %s\n", identity, content);

                        // Send 0..4 replies back
                        int reply, replies = request_nbr; // rand() % 5;
                        for (reply = 0; reply < replies; reply++) {
                            // Sleep for some fraction of a second
                            msleep (rand () % 10 + 1);
                            //  Send message from server to client
                            rc = zmq_send (worker, identity, ID_SIZE, ZMQ_SNDMORE);
                            assert (rc == ID_SIZE);
                            rc = zmq_send (worker, content, CONTENT_SIZE, 0);
                            assert (rc == CONTENT_SIZE);
                        }
                    }
                }
            }
            sprintf(content, "request #%03d", ++request_nbr); // CONTENT_SIZE
            if (request_nbr <= QT_REQUESTS) {
                rc = zmq_send (client, content, CONTENT_SIZE, 0);
                assert (rc == CONTENT_SIZE);
            }
        }
        if (round_ == 0) { // --------------------------------------------------------------------------- TODO
            // change the topology
//            frontends[1] = NULL;   frontends[2] = NULL;
//            backends[1] =  worker; backends[2] =  NULL;
//            worker_socket_pos = 2;
//            msleep(100);  // still error
//            rc = zmq_disconnect (worker, backend_addr); // fails !!!
//            assert (rc == 0);
//            rc = zmq_disconnect (frontend, client_addr);
//            assert (rc == 0);
    //            rc = zmq_close (worker);
    //            printf("Error: zmq_disconnect failed: %s (%d)\n", zmq_strerror(errno), zmq_errno());
    //            assert (rc == 0);
    //            void *worker = zmq_socket (ctx, ZMQ_DEALER);
    //            assert (worker);
//            rc = zmq_bind (worker, client_addr);
//            assert (rc == 0);
            zmq_proxy_open_chain (NULL, NULL, NULL, NULL, NULL, NULL, 0); // reinitialise the LTS variables
        }
    }

    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (frontend);
    assert (rc == 0);
    rc = zmq_close (intermediate1);
    assert (rc == 0);
    rc = zmq_close (intermediate2);
    assert (rc == 0);
    rc = zmq_close (backend);
    assert (rc == 0);
    rc = zmq_close (worker);
    assert (rc == 0);
}

int
main (void)
{
#ifdef thread_local
    setup_test_environment ();
    void *ctx = zmq_ctx_new ();
    assert (ctx);
    assert(QT_THREADS > 0);
    void *threads [QT_THREADS];
    memset(count, 0, QT_THREADS);

    for (int i = 0; i < QT_THREADS; i++) {
        config_t *config = (config_t *) malloc(sizeof(config_t));
        config->ctx = ctx;
        config->index = i;
        threads[i] = zmq_threadstart (&do_some_stuff, (void*) config);
    }

    for (int i = 0; i < QT_THREADS; i++)
        zmq_threadclose (threads[i]);
    int rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    assert(count[0]); // at least one message received
    for (int i = 1; i < QT_THREADS; i++)
        assert(count[0] == count[i]); // check that we have received the same number of messages on each thread - weak but enough condition
    if (is_verbose)
        printf ("All threads have received %d messages\n", count[0]);
#endif
    return 0;
}
