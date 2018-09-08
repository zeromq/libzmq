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

//
// Asynchronous proxy test using ZMQ_XPUB_NODROP and HWM:
//
// Topology:
//
//   PUB                       SUB
//    |                         |
//    \-----> XSUB -> XPUB -----/
//           ^^^^^^^^^^^^^^
//             ZMQ proxy
//
// All connections use "inproc" transport and have artificially-low HWMs set.
// Then the PUB socket starts flooding the Proxy. The SUB is artificially slow
// at receiving messages.
// This scenario simulates what happens when a SUB is slower than
// its PUB: since ZMQ_XPUB_NODROP=1, the XPUB will block and then
// also the PUB socket will block.
// The result is that 2*HWM messages will be sent before the PUB blocks.
//
// In the meanwhile asking statistics to the Proxy must NOT be blocking.
//


#define HWM							10
#define NUM_BYTES_PER_MSG			50000

#if 0	// enable for debugging this test
#define UNIT_TEST_LOG(...)			do { printf(__VA_ARGS__); printf("\n"); } while(0)
#else
#define UNIT_TEST_LOG(...)			/* empty */
#endif

typedef struct
{
	void* context;
	const char* frontend_endpoint;
	const char* backend_endpoint;
	const char* control_endpoint;

	bool subscriber_received_all;
} proxy_hwm_cfg_t;

static
void lower_tcp_buff(void* sock_)
{
	int sndBuff;
	size_t sndBuffSz = sizeof sndBuff;
	int rc = zmq_getsockopt (sock_, ZMQ_SNDBUF, &sndBuff, &sndBuffSz);
	assert (rc == 0);
	UNIT_TEST_LOG("lower_tcp_buff current TCP buffer size = %d", sndBuff);

	int newBuff = 1000;
	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_setsockopt (sock_, ZMQ_SNDBUF, &newBuff, sizeof (newBuff)));

	rc = zmq_getsockopt (sock_, ZMQ_SNDBUF, &sndBuff, &sndBuffSz);
	assert (rc == 0);
	UNIT_TEST_LOG("lower_tcp_buff new TCP buffer size = %d", sndBuff);
}

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
	TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (pubsocket, cfg->frontend_endpoint));

	int optval = 1;
	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_setsockopt (pubsocket, ZMQ_XPUB_NODROP, &optval, sizeof (optval)));

	UNIT_TEST_LOG("publisher_thread_main waiting %dmsec to allow subscribers to REALLY connect", SETTLE_TIME);
	msleep (SETTLE_TIME);

	uint64_t send_count = 0;
	while (true)
	{
		zmq_msg_t msg;
		int rc = zmq_msg_init_size (&msg, NUM_BYTES_PER_MSG);
		assert (rc == 0);

		/* Fill in message content with 'AAAAAA' */
		memset (zmq_msg_data (&msg), 'A', NUM_BYTES_PER_MSG);

		/* Send the message to the socket */
		rc = zmq_msg_send(&msg, pubsocket, ZMQ_DONTWAIT);
		if (rc != -1)
		{
			UNIT_TEST_LOG(" ** publisher_thread_main sent successfully %d bytes sent, total sent %lu", rc, send_count);
			send_count++;
		}
		else
		{
			UNIT_TEST_LOG(" ** publisher_thread_main failed sending pkt with errno=%d", zmq_errno());
			break;
		}
	}

	// VERIFY EXPECTED RESULTS

	UNIT_TEST_LOG("publisher_thread_main sent %lu packets successfully.", send_count);
	TEST_ASSERT_EQUAL_INT( 2*HWM, send_count );


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
	TEST_ASSERT_SUCCESS_ERRNO (
	  zmq_connect (subsocket, cfg->backend_endpoint));

	lower_tcp_buff(subsocket);

	// receive all sent messages
	uint64_t rxsuccess = 0;
	bool success = true;
	while (success)
	{
		zmq_msg_t msg;
		int rc = zmq_msg_init(&msg);
		assert (rc == 0);

		rc = zmq_msg_recv(&msg, subsocket, 0);
		if (rc != -1)
		{
			UNIT_TEST_LOG(" ** received %lu pkts", rxsuccess);
			rxsuccess++;

			// after receiving 1st message, set a finite timeout (default is infinite)
			int timeout_ms = 100;
			TEST_ASSERT_SUCCESS_ERRNO (
			  zmq_setsockopt (subsocket, ZMQ_RCVTIMEO, &timeout_ms, sizeof(timeout_ms)));
		}
		else
		{
			UNIT_TEST_LOG(" ** failed receiving...  exiting");
			break;
		}

		msleep(100);
	}


	// VERIFY EXPECTED RESULTS

	//UNIT_TEST_LOG("subscriber_thread_main received %lu packets successfully; %lu packets RX failed.",
	//		rxsuccess, rxfailed );
	//assert( rxsuccess == 1 );
	TEST_ASSERT_EQUAL_INT( 2*HWM, rxsuccess );


	// INFORM THAT WE COMPLETED:

	cfg->subscriber_received_all = true;


	// CLEANUP

	zmq_close(subsocket);

	UNIT_TEST_LOG("subscriber_thread_main exiting");
}

bool recv_stat (void *sock_, bool last_, uint64_t* res)
{
	zmq_msg_t stats_msg;

	int rc = zmq_msg_init (&stats_msg);
	assert (rc == 0);

	rc = zmq_msg_recv (&stats_msg, sock_, 0); //ZMQ_DONTWAIT);
	if (rc == -1 && errno == EAGAIN)
	{
		rc = zmq_msg_close (&stats_msg);
		assert (rc == 0);
		return false;				// cannot retrieve the stat
	}

	assert (rc == sizeof (uint64_t));
	memcpy (res, zmq_msg_data (&stats_msg), zmq_msg_size (&stats_msg));

	rc = zmq_msg_close (&stats_msg);
	assert (rc == 0);

	int more;
	size_t moresz = sizeof more;
	rc = zmq_getsockopt (sock_, ZMQ_RCVMORE, &more, &moresz);
	assert (rc == 0);
	assert ((last_ && !more) || (!last_ && more));

	return true;
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

bool check_proxy_stats (void *control_proxy_)
{
	zmq_proxy_stats_t total_stats;
	int rc;

	static unsigned int nupdates = 0, nsuccess = 0, nfailed = 0;
	bool is_verbose = (((nupdates++)%1000) == 0);

	if (is_verbose)
		UNIT_TEST_LOG("asking update #%d from proxy (so far %d successful, %d failed):", nupdates, nsuccess, nfailed);

	rc = zmq_send (control_proxy_, "STATISTICS", 10, ZMQ_DONTWAIT);
	assert (rc == 10 ||
			(rc == -1 && errno == EAGAIN));
	if (rc == -1 && errno == EAGAIN)
	{
		nfailed++;
		if (is_verbose) UNIT_TEST_LOG("    ...failed (TX)");
		return false;
	}

	// first frame of the reply contains FRONTEND stats:
	if (!recv_stat( control_proxy_, false, &total_stats.frontend.msg_in ))
	{
		nfailed++;
		if (is_verbose) UNIT_TEST_LOG("    ...failed (timedout)");
		return false;
	}

	recv_stat( control_proxy_, false, &total_stats.frontend.bytes_in );
	recv_stat( control_proxy_, false, &total_stats.frontend.msg_out );
	recv_stat( control_proxy_, false, &total_stats.frontend.bytes_out );

	// second frame of the reply contains BACKEND stats:
	recv_stat( control_proxy_, false, &total_stats.backend.msg_in );
	recv_stat( control_proxy_, false, &total_stats.backend.bytes_in );
	recv_stat( control_proxy_, false, &total_stats.backend.msg_out );
	recv_stat( control_proxy_, true,  &total_stats.backend.bytes_out );

	// check stats

	if (is_verbose) {
		UNIT_TEST_LOG (
		  "frontend: pkts_in=%lu bytes_in=%lu  pkts_out=%lu bytes_out=%lu\n",
		  (unsigned long int) total_stats.frontend.msg_in,
		  (unsigned long int) total_stats.frontend.bytes_in,
		  (unsigned long int) total_stats.frontend.msg_out,
		  (unsigned long int) total_stats.frontend.bytes_out);
		UNIT_TEST_LOG (
		  "backend: pkts_in=%lu bytes_in=%lu  pkts_out=%lu bytes_out=%lu\n",
		  (unsigned long int) total_stats.backend.msg_in,
		  (unsigned long int) total_stats.backend.bytes_in,
		  (unsigned long int) total_stats.backend.msg_out,
		  (unsigned long int) total_stats.backend.bytes_out);
	}

	nsuccess++;
	return true;
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


	// IMPORTANT: by setting the tx/rx timeouts, we avoid getting blocked when interrogating a proxy which is
	//            itself blocked in a zmq_msg_send() on its XPUB socket having ZMQ_XPUB_NODROP=1!

	int optval = 10;
	rc = zmq_setsockopt(control_req, ZMQ_SNDTIMEO, &optval, sizeof(optval));
	assert( rc == 0 );
	rc = zmq_setsockopt(control_req, ZMQ_RCVTIMEO, &optval, sizeof(optval));
	assert( rc == 0 );

	optval = 10;
	rc = zmq_setsockopt(control_req, ZMQ_REQ_CORRELATE, &optval, sizeof(optval));
	assert( rc == 0 );

	rc = zmq_setsockopt(control_req, ZMQ_REQ_RELAXED, &optval, sizeof(optval));
	assert( rc == 0 );


	// Start!

	while (!cfg->subscriber_received_all)
	{
#ifdef ZMQ_BUILD_DRAFT_API
		check_proxy_stats(control_req);
#endif
		usleep(1000);			// 1ms -> in best case we will get 1000updates/second
	}


	// Ask the proxy to exit: the subscriber has received all messages

	rc = zmq_send (control_req, "TERMINATE", 9, 0);
	assert (rc == 9);

	zmq_close( control_req );

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

	zmq_close( frontend_xsub );
	zmq_close( backend_xpub );
	zmq_close( control_rep );

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
	cfg.backend_endpoint = "inproc://backend";
	cfg.control_endpoint = "inproc://ctrl";
	cfg.subscriber_received_all = false;

	void* proxy = zmq_threadstart(&proxy_thread_main, (void*) &cfg);
	assert(proxy != 0);
	void* publisher = zmq_threadstart(&publisher_thread_main, (void*) &cfg);
	assert(publisher != 0);
	void* subscriber = zmq_threadstart(&subscriber_thread_main, (void*) &cfg);
	assert(subscriber != 0);
	void* asker = zmq_threadstart(&proxy_stats_asker_thread_main, (void*) &cfg);
	assert(asker != 0);


	// CLEANUP

	UNIT_TEST_LOG("main waiting for all threads to join");

	zmq_threadclose (publisher);
	zmq_threadclose (subscriber);
	zmq_threadclose (asker);
	zmq_threadclose (proxy);

	int rc = zmq_ctx_term (context);
	assert (rc == 0);

	return 0;
}
