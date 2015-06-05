#include "testutil.hpp"

void test_valid_hwm_change()
{
  void *ctx = zmq_ctx_new ();
  assert (ctx);
  int rc;

  void *bind_socket = zmq_socket (ctx, ZMQ_SUB);
  assert (bind_socket);

  int val = 500;
  rc = zmq_setsockopt(bind_socket, ZMQ_RCVHWM, &val, sizeof(val));
  assert (rc == 0);

  rc = zmq_bind (bind_socket, "inproc://a");
  assert (rc == 0);

  size_t placeholder = sizeof(val);
  val = 0;
  rc = zmq_getsockopt(bind_socket, ZMQ_RCVHWM, &val, &placeholder);
  assert (rc == 0);
  assert(val == 500);
}


/**
 * Test that zmq_setsockopt() fails to change the RCVHWM when called
 * after a call to zmq_bind().
 */
void test_invalid_hwm_change_bind()
{
  void *ctx = zmq_ctx_new ();
  assert (ctx);
  int rc;

  void *bind_socket = zmq_socket (ctx, ZMQ_SUB);
  assert (bind_socket);

  rc = zmq_bind (bind_socket, "inproc://a");
  assert (rc == 0);

  int val = 500;
  rc = zmq_setsockopt (bind_socket, ZMQ_RCVHWM, &val, sizeof(val));
  assert (rc == -1);

  zmq_close (bind_socket);
  zmq_ctx_term (ctx);
}

void test_invalid_hwm_change_connect()
{
	void *ctx = zmq_ctx_new();
	assert(ctx);
	int rc;

	void *connect_socket = zmq_socket (ctx, ZMQ_SUB);
	assert(connect_socket);

	rc = zmq_connect (connect_socket, "inproc://a");
	assert(rc == 0);

	int val = 500;
	rc = zmq_setsockopt (connect_socket, ZMQ_RCVHWM, &val, sizeof(val));
	assert(rc == -1);

	zmq_close (connect_socket);
	zmq_ctx_term (ctx);
}


int main()
{
  test_valid_hwm_change();
  test_invalid_hwm_change_bind();
  test_invalid_hwm_change_connect();
}
