/*
Server thread listen ZMQ_SERVER socket and transfer incoming message 
to worker threads by ZMQ_PUSH-ZMQ_PULL
Worker thread receive message and send back to ZMQ_SERVER socket

Each client thread open CLIENT_CONNECTION ZMQ_CLIENT sockets, 
send random size message to each socket and check server answer
*/

#define ZMQ_BUILD_DRAFT_API
#include "../../../../include/zmq.h"

#pragma comment(lib,"libzmq.lib")

#include <assert.h>
#include <stdlib.h>
#include <thread>
#include <atomic>

#define SERVER_ADDR "tcp://127.0.0.1:12345"
#define SERVER_WORKER_COUNT 3	// worker threads count

#define CLIENT_COUNT 5			// client threads count
#define CLIENT_CONNECTION 100	// ZMQ_CLIENT sockets at each client
#define CLIENT_RECCONECT 1000	// reconnect one socket after messages

#define MESSAGE_MAX_SIZE 1024

//*******************************************************************
//****** MESSAGE ****************************************************
//*******************************************************************

void message_fill(zmq_msg_t* msg, int val) {
	assert(val > 0);
	int size = sizeof(int) * 2 + val;
	int rc = zmq_msg_init_size(msg, size); assert(rc == 0);
	uint8_t* data = (uint8_t*)zmq_msg_data(msg);
	memcpy(data, &val, sizeof(int));
	data += sizeof(int);
	memset(data, val & 0xFF, val);
	int check_sum = val + (val & 0xFF) * val;
	data += val;
	memcpy(data, &check_sum, sizeof(int));
}

int message_check(zmq_msg_t* msg) {
	uint8_t* data = (uint8_t*)zmq_msg_data(msg);
	int size = zmq_msg_size(msg);
	assert(size > sizeof(int) * 2);
	// check size
	int val;
	memcpy(&val, data, sizeof(int));
	if(size != sizeof(int) * 2 + val) { 
		fprintf(stderr, "wrong message: val = %d size = %d\n", val, size);
		return -1;
	}
	// check sum
	data += sizeof(int);
	int cs = val;
	for(int i = 0; i < val; i++) {
		cs += data[i];
	}
	data += val;
	int check_sum;
	memcpy(&check_sum, data, sizeof(int));
	if(check_sum != cs) {
		fprintf(stderr, "wrong message: cs = %d check_sum = %d\n", cs, check_sum);
		return -1;
	}
	return val;
}

//*******************************************************************
//****** SERVER *****************************************************
//*******************************************************************

void *server_ctx = NULL;
void *server_sock = NULL;

std::atomic<int> worker_cnt[SERVER_WORKER_COUNT] = {0}; // statistic

// worker thread
void worker(int num) {
	printf("worker %d start\n", num);
	void* queue = zmq_socket(server_ctx, ZMQ_PULL); assert(queue);
	int rc = zmq_connect(queue, "inproc://queue"); assert(rc == 0);

	while (1) {
		// receive messages from the queue
		zmq_msg_t msg;
		rc = zmq_msg_init(&msg); assert(rc == 0);
		rc = zmq_msg_recv(&msg, queue, 0); assert(rc > 0);
		// check message
		//printf("worker %d recv %d bytes at %X from %X\n", num, zmq_msg_size(&msg), zmq_msg_data(&msg), zmq_msg_routing_id(&msg));
		// send to client
		rc = zmq_msg_send(&msg, server_sock, 0); assert(rc != -1);
		worker_cnt[num]++;
	}
	zmq_close(queue);
}

// server thread
void server() {
	server_ctx = zmq_ctx_new(); assert(server_ctx);
	// create queue
	void* queue = zmq_socket(server_ctx, ZMQ_PUSH);	assert(queue);
	int rc = zmq_bind(queue, "inproc://queue"); assert(rc == 0);
	// start workers
	std::thread w[SERVER_WORKER_COUNT];
	for (int i = 0; i < SERVER_WORKER_COUNT; i++) w[i] = std::thread(worker, i);
	// ZMQ_SERVER for client messages
	server_sock = zmq_socket(server_ctx, ZMQ_SERVER); assert(server_sock);
	rc = zmq_bind(server_sock, SERVER_ADDR); assert(rc == 0);

	while (1) {
		// wait client message
		zmq_msg_t msg;
		rc = zmq_msg_init(&msg); assert(rc == 0); 
		rc = zmq_msg_recv(&msg, server_sock, 0); assert(rc > 0);
		//printf("recv %d bytes at %X from %X\n", zmq_msg_size(&msg), zmq_msg_data(&msg), zmq_msg_routing_id(&msg));
		// send message to queue
		rc = zmq_msg_send(&msg, queue, 0); assert(rc > 0);
	}
}

//*******************************************************************
//****** CLIENT *****************************************************
//*******************************************************************

std::atomic<int> client_cnt[CLIENT_COUNT] = { 0 }; // statistic
std::atomic<int> client_ready = 0; 

// client thread
void client(int num)
{
	//printf("client %d start. Open %d connections\n", num, CLIENT_CONNECTION);

	void *ctx = zmq_ctx_new(); assert(ctx);

	void *sock[CLIENT_CONNECTION];
	int rc;
	// open ZMQ_CLIENT connections
	for (int i = 0; i < CLIENT_CONNECTION; i++) {
		sock[i] = zmq_socket(ctx, ZMQ_CLIENT); assert(sock[i]);
		rc = zmq_connect(sock[i], SERVER_ADDR); assert(rc == 0);
		// test connection
		zmq_msg_t msg;
		int v = rand() % 256 + 1;
		message_fill(&msg, v);
		rc = zmq_msg_send(&msg, sock[i], 0); assert(rc > 0);
		rc = zmq_msg_init(&msg); assert(rc == 0);
		rc = zmq_msg_recv(&msg, sock[i], 0); assert(rc > 0);
		rc = message_check(&msg); assert(rc == v);
		zmq_msg_close(&msg);
	}
	printf("client %d open %d connections\n", num, CLIENT_CONNECTION);
	client_ready++;
	while (client_ready < CLIENT_COUNT) Sleep(10); // wait while all clients open sockets

	int recconect = 0;
	while(1) {
		int val[CLIENT_CONNECTION];
		zmq_msg_t msg;
		// send messages
		for(int i = 0; i < CLIENT_CONNECTION; i++) {
			val[i] = rand() % MESSAGE_MAX_SIZE + 1;
			message_fill(&msg, val[i]);
			rc = zmq_msg_send(&msg, sock[i], 0); assert(rc > 0);
		}
		// recv and check
		for (int i = 0; i < CLIENT_CONNECTION; i++) {
			rc = zmq_msg_init(&msg); assert(rc == 0);
			rc = zmq_msg_recv(&msg, sock[i], 0); assert(rc > 0);
			rc = message_check(&msg);
			if(rc != val[i] && rc > 0) {
				fprintf(stderr, "wrong message: send %d recv %d     \n", val[i], rc);
			}
			zmq_msg_close(&msg);
			client_cnt[num]++;
		}
		// reconnect one
		recconect++;
		if(recconect == CLIENT_RECCONECT) {
			int n = rand() % CLIENT_CONNECTION;
			zmq_close(sock[n]);
			sock[n] = zmq_socket(ctx, ZMQ_CLIENT); assert(sock[n]);
			int rc = zmq_connect(sock[n], SERVER_ADDR); assert(rc == 0);
		}
	}
}

//*******************************************************************
int main (void) {
	int v1, v2, v3; zmq_version(&v1, &v2, &v3);
	printf("ZMQ version %d.%d.%d. Compile %s %s\n", v1, v2, v3, __DATE__, __TIME__);

	std::thread ct[CLIENT_COUNT];
	for (int i = 0; i < CLIENT_COUNT; i++) ct[i] = std::thread(client, i);

	std::thread st(server);

	int w[SERVER_WORKER_COUNT] = { 0 };
	int c[CLIENT_COUNT] = { 0 };
	int total = 0;

	while(1) {
		Sleep(1000);
		if (client_ready < CLIENT_COUNT) continue;
		// check workers
		for(int i = 0; i < SERVER_WORKER_COUNT; i++) {
			if(w[i] == worker_cnt[i]) {
				fprintf(stderr, "worker %d not work        \n", i);
			}
			w[i] = worker_cnt[i];
		}
		// check clients
		int t = 0;
		for (int i = 0; i < CLIENT_COUNT; i++) {
			if (c[i] == client_cnt[i]) {
				fprintf(stderr, "client %d not work        \n", i);
			}
			c[i] = client_cnt[i];
			t += c[i];
		}
		printf("\rTotal %d messages. Speed %d per second  ", t, t - total);
		total = t;
	}
	return 0;
}
