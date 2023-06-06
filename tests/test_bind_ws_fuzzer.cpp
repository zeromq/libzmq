/* SPDX-License-Identifier: MPL-2.0 */

#ifdef ZMQ_USE_FUZZING_ENGINE
#include <fuzzer/FuzzedDataProvider.h>
#endif

#include "testutil.hpp"
#include "testutil_unity.hpp"

// Test that the ZMTP WebSocket engine handles invalid handshake when connecting
// https://rfc.zeromq.org/spec/45/
extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
    setup_test_context ();
    char my_endpoint[MAX_SOCKET_STRING];
    size_t my_endpoint_size = sizeof (my_endpoint);
    void *server = test_context_socket (ZMQ_DEALER);
    //  As per API by default there's no limit to the size of a message,
    //  but the sanitizer allocator will barf over a gig or so
    int64_t max_msg_size = 64 * 1024 * 1024;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof (int64_t)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (server, "ws://127.0.0.1:*"));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_getsockopt (server, ZMQ_LAST_ENDPOINT,
                                               my_endpoint, &my_endpoint_size));
    //  Remove trailing /
    my_endpoint[my_endpoint_size - 2] = '\0';
    fd_t client = connect_socket (my_endpoint, AF_INET, IPPROTO_WS);

    void *client_good = test_context_socket (ZMQ_DEALER);
    my_endpoint[my_endpoint_size - 2] = '/';
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client_good, my_endpoint));

    //  If there is not enough data for a full handshake, just send what we can
    //  Otherwise send websocket handshake first, as expected by the protocol
    uint8_t buf[256];
    if (size >= 192) {
        send (client, (void *) data, 192, MSG_NOSIGNAL);
        data += 192;
        size -= 192;
    }
    recv (client, buf, 256, MSG_DONTWAIT);
    msleep (250);
    for (ssize_t sent = 0; size > 0 && (sent != -1 || errno == EINTR);
         size -= sent > 0 ? sent : 0, data += sent > 0 ? sent : 0)
        sent = send (client, (const char *) data, size, MSG_NOSIGNAL);
    msleep (250);
    recv (client, buf, 256, MSG_DONTWAIT);

    zmq_msg_t msg;
    zmq_msg_init (&msg);
    while (-1 != zmq_msg_recv (&msg, server, ZMQ_DONTWAIT)) {
        zmq_msg_close (&msg);
        zmq_msg_init (&msg);
    }

    send_string_expect_success (client_good, "abc", 0);
    recv_string_expect_success (server, "abc", 0);

    close (client);
    test_context_socket_close_zero_linger (client_good);
    test_context_socket_close_zero_linger (server);
    teardown_test_context ();

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_bind_ws_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_bind_ws_fuzzer_seed_corpus", &data,
          &len, &num_cases)
        != 0)
        exit (77);

    while (num_cases-- > 0) {
        TEST_ASSERT_SUCCESS_ERRNO (
          LLVMFuzzerTestOneInput (data[num_cases], len[num_cases]));
        free (data[num_cases]);
    }

    free (data);
    free (len);
}

int main (int argc, char **argv)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_bind_ws_fuzzer);

    return UNITY_END ();
}
#endif
