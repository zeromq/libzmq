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

#include <unity.h>


// Asynchronous proxy test using ZMQ_XPUB_NODROP and HWM

#define HWM					50
#define NUM_MSGS			10000
#define NUM_BYTES_PER_MSG	50000
#define UNIT_TEST_LOG(...)			do { printf(__VA_ARGS__); printf("\n"); } while(0)

typedef struct
{
	void* context;
	const char* frontend_endpoint;
	const char* backend_endpoint;
	const char* control_endpoint;

	bool subscriber_received_all;
} proxy_hwm_cfg_t;

#if 0
static
void lower_tcp_buff(void* sock_)
{
	int iSockFd;
	size_t fdsz = sizeof iSockFd;
	int rc = zmq_getsockopt (sock_, ZMQ_FD, &iSockFd, &fdsz);
	assert (rc == 0);

	int n = 0; socklen_t sl = sizeof(n);
	if ( 0 != getsockopt(iSockFd,SOL_SOCKET,SO_RCVBUF, &n, &sl))
	{
		printf("Get socket option failed, errno: %d\n",errno);
	}
	else
	{
		printf("Current socket buff len = %d\n", n);
	}
	n = 1024;
	if(0 != setsockopt(iSockFd, SOL_SOCKET, SO_RCVBUF, (const void *)&n, sizeof(n)))
	{
		printf("setsock err errno %d\n", errno);
	}
	else
	{
		printf("setsock opt success\n");
	}
	n = 0;
	if ( 0 != getsockopt(iSockFd,SOL_SOCKET,SO_RCVBUF, &n, &sl))
	{
		printf("Get socket option failed, errno: %d\n",errno);
	}
	else
	{
		printf("After setting socket buff len = %d\n", n);
	}
}
#endif

static
void lower_hwm(void* skt)
{
	int send_hwm_ = HWM;
	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_setsockopt (skt, ZMQ_SNDHWM, &send_hwm_, sizeof (send_hwm_)));

	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_setsockopt (skt, ZMQ_RCVHWM, &send_hwm_, sizeof (send_hwm_)));
}


static
void publisher_thread_main(void* pvoid)
{
	UNIT_TEST_LOG("publisher_thread_main started");
	proxy_hwm_cfg_t* cfg = (proxy_hwm_cfg_t*)pvoid;

	void* pubsocket = zmq_socket(cfg->context, ZMQ_PUB);
	assert(pubsocket);

	lower_hwm(pubsocket);

	UNIT_TEST_LOG("publisher_thread_main connecting to endpoint %s", cfg->frontend_endpoint);
	int rc = zmq_connect(pubsocket, cfg->frontend_endpoint);
	assert (rc==0);

	int optval = 1;
	rc = zmq_setsockopt(pubsocket, ZMQ_XPUB_NODROP, &optval, sizeof(optval));
	assert( rc == 0 );


	//UNIT_TEST_LOG("publisher_thread_main waiting for the barrier");
	//pthread_barrier_wait(&cfg->unit_test_barrier);
	//UNIT_TEST_LOG("publisher_thread_main completed waiting for the barrier");

	UNIT_TEST_LOG("publisher_thread_main waiting %dmsec to allow subscribers to REALLY connect", SETTLE_TIME);
	msleep (SETTLE_TIME);
	msleep (10*SETTLE_TIME);

	uint64_t txfailed = 0;
	for (uint64_t i = 0 ; i < NUM_MSGS ; ++i)
	{
		zmq_msg_t msg;
		int rc = zmq_msg_init_size (&msg, NUM_BYTES_PER_MSG);
		assert (rc == 0);

		/* Fill in message content with 'AAAAAA' */
		memset (zmq_msg_data (&msg), 'A', NUM_BYTES_PER_MSG);

		/* Send the message to the socket */
		rc = zmq_msg_send(&msg, pubsocket, 0);
		//assert (rc == 0);
		if (rc != -1)
		{
			UNIT_TEST_LOG(" ** publisher_thread_main sent successfully pkt #%zu, %d bytes sent, total failed %lu", i, rc, txfailed);
		}
		else
		{
			UNIT_TEST_LOG(" ** publisher_thread_main failed sending pkt #%zu with errno=%d", i, zmq_errno());
			txfailed++;
		}
	}

	// VERIFY EXPECTED RESULTS

	UNIT_TEST_LOG("publisher_thread_main sent %lu packets successfully; %lu packets TX failed.",
			NUM_MSGS-txfailed, txfailed );
	assert( txfailed == 0 );


	// CLEANUP

	zmq_close( pubsocket );
	UNIT_TEST_LOG("publisher_thread_main exiting");
}

static
void subscriber_thread_main(void* pvoid)
{
	UNIT_TEST_LOG("subscriber_thread_main started");
	proxy_hwm_cfg_t* cfg = (proxy_hwm_cfg_t*)pvoid;

	void* subsocket = zmq_socket(cfg->context, ZMQ_SUB);
	assert(subsocket);

	lower_hwm(subsocket);

	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_setsockopt (subsocket, ZMQ_SUBSCRIBE, 0, 0));

	UNIT_TEST_LOG("subscriber_thread_main connecting to endpoint %s", cfg->backend_endpoint);
	TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subsocket, cfg->backend_endpoint));

	//lower_tcp_buff(subsocket);

	//UNIT_TEST_LOG("subscriber_thread_main waiting for the barrier");
	//pthread_barrier_wait(&cfg->unit_test_barrier);
	//UNIT_TEST_LOG("subscriber_thread_main completed waiting for the barrier");

	// receive all sent messages
	uint64_t rxfailed = 0, rxsuccess = 0;
	bool success = true;
	while (success)
	{
		zmq_msg_t msg;
		int rc = zmq_msg_init(&msg);
		assert (rc == 0);

		rc = zmq_msg_recv(&msg, subsocket, 0);//ZMQ_DONTWAIT);
		if (rc != -1)
		{
			UNIT_TEST_LOG(" ** received %lu pkts, total failed %lu", rxsuccess, rxfailed);
			rxsuccess++;
		}
		else
		{
			UNIT_TEST_LOG(" ** failed receiving... total failed %lu", rxfailed);
			rxfailed++;
		}

		msleep(100);
	}


	// VERIFY EXPECTED RESULTS

	UNIT_TEST_LOG("subscriber_thread_main received %lu packets successfully; %lu packets RX failed.",
			rxsuccess, rxfailed );
	assert( rxfailed == 1 );


	// INFORM THAT WE COMPLETED:

	cfg->subscriber_received_all = true;


	// CLEANUP

	zmq_close(subsocket);

	UNIT_TEST_LOG("subscriber_thread_main exiting");
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

void check_proxy_stats (void *control_proxy_, bool is_verbose)
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
    }
}

static
void proxy_stats_asker_thread_main(void* pvoid)
{
	UNIT_TEST_LOG("proxy_stats_asker_thread_main started");
	proxy_hwm_cfg_t* cfg = (proxy_hwm_cfg_t*)pvoid;


	// CONTROL REQ

	void* control_req = zmq_socket(cfg->context, ZMQ_REQ);			// this one can be used to send command to the proxy
	assert(control_req);

	// connect CONTROL-REQ: a socket to which send commands
	UNIT_TEST_LOG("proxy_stats_asker_thread_main connecting to endpoint %s", cfg->control_endpoint);
	int rc = zmq_connect(control_req, cfg->control_endpoint);
	assert( rc == 0 );

	//UNIT_TEST_LOG("proxy_stats_asker_thread_main waiting for the barrier");
	//pthread_barrier_wait(&cfg->unit_test_barrier);
	//UNIT_TEST_LOG("proxy_stats_asker_thread_main completed waiting for the barrier");

	// Start!

	unsigned int nupdates = 0;
	while (!cfg->subscriber_received_all)
	{
		usleep(10);
		//sleep(3);

		check_proxy_stats(control_req, nupdates%10000);
		nupdates++;
		/*if ((nupdates%10000) == 0)
		{
			UNIT_TEST_LOG("proxy_stats_asker_thread_main completed update %d from proxy", nupdates);
		}*/
	}

	UNIT_TEST_LOG("proxy_stats_asker_thread_main exiting");
}

static
void proxy_thread_main(void* pvoid)
{
	UNIT_TEST_LOG("proxy_thread_main started");
	proxy_hwm_cfg_t* cfg = (proxy_hwm_cfg_t*)pvoid;
	int rc;


	// FRONTEND SUB

	void* frontend_xsub = zmq_socket(cfg->context, ZMQ_XSUB);		// the frontend is the one exposed to internal threads (INPROC)
	assert(frontend_xsub);

	lower_hwm(frontend_xsub);

	// bind FRONTEND
	rc = zmq_bind(frontend_xsub, cfg->frontend_endpoint);
	assert( rc == 0 );



	// BACKEND PUB

	void* backend_xpub = zmq_socket(cfg->context, ZMQ_XPUB);			// the backend is the one exposed to the external world (TCP)
	assert(backend_xpub);

	int optval = 1;
	rc = zmq_setsockopt(backend_xpub, ZMQ_XPUB_NODROP, &optval, sizeof(optval));
	assert( rc == 0 );

	lower_hwm(backend_xpub);

	// bind BACKEND
	rc = zmq_bind(backend_xpub, cfg->backend_endpoint);
	assert( rc == 0 );


	// CONTROL REP

	void* control_rep = zmq_socket(cfg->context, ZMQ_REP);			// this one is used by the proxy to receive&reply to commands
	assert(control_rep);

	// bind CONTROL
	rc = zmq_bind(control_rep, cfg->control_endpoint);
	assert( rc == 0 );



	// start proxying!

	UNIT_TEST_LOG("proxy_thread_main starting proxy on frontend=%s, backend=%s, ctrl=%s",
				cfg->frontend_endpoint, cfg->backend_endpoint, cfg->control_endpoint);

	zmq_proxy_steerable(frontend_xsub,
						backend_xpub,
						NULL,
						control_rep);

	UNIT_TEST_LOG("proxy_thread_main exiting");
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
	cfg.backend_endpoint = ENDPOINT_0;
	//cfg.backend_endpoint = "inproc://backend";
	cfg.control_endpoint = "inproc://ctrl";
	cfg.subscriber_received_all = false;

	void* proxy = zmq_threadstart(&proxy_thread_main, (void*) &cfg);
	assert(proxy != 0);
	void* server = zmq_threadstart(&publisher_thread_main, (void*) &cfg);
	assert(server != 0);
	void* client = zmq_threadstart(&subscriber_thread_main, (void*) &cfg);
	assert(client != 0);
	void* asker = zmq_threadstart(&proxy_stats_asker_thread_main, (void*) &cfg);
	assert(asker != 0);


	// CLEANUP

	UNIT_TEST_LOG("main waiting for all threads to join");

	zmq_threadclose (server);
	zmq_threadclose (client);
	zmq_threadclose (asker);
	zmq_threadclose (proxy);

	int rc = zmq_ctx_term (context);
	assert (rc == 0);

	return 0;
}
