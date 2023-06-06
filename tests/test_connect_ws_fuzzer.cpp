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
    fd_t server = bind_socket_resolve_port ("127.0.0.1", "0", my_endpoint,
                                            AF_INET, IPPROTO_WS);

    void *client = test_context_socket (ZMQ_PULL);
    //  As per API by default there's no limit to the size of a message,
    //  but the sanitizer allocator will barf over a gig or so
    int64_t max_msg_size = 64 * 1024 * 1024;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (client, ZMQ_MAXMSGSIZE, &max_msg_size, sizeof (int64_t)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (client, my_endpoint));

    fd_t server_accept =
      TEST_ASSERT_SUCCESS_RAW_ERRNO (accept (server, NULL, NULL));

    //  If there is not enough data for a full handshake, just send what we can
    //  Otherwise send websocket handshake first, as expected by the protocol
    uint8_t buf[256];
    recv (server_accept, buf, 256, 0);
    if (size >= 166) {
        send (server_accept, (void *) data, 166, MSG_NOSIGNAL);
        data += 166;
        size -= 166;
    }
    recv (server_accept, buf, 256, MSG_DONTWAIT);
    //  Then send the READY command
    if (size >= 29) {
        send (server_accept, (void *) data, 29, MSG_NOSIGNAL);
        data += 29;
        size -= 29;
    }
    msleep (250);
    for (ssize_t sent = 0; size > 0 && (sent != -1 || errno == EINTR);
         size -= sent > 0 ? sent : 0, data += sent > 0 ? sent : 0)
        sent = send (server_accept, (const char *) data, size, MSG_NOSIGNAL);
    msleep (250);

    zmq_msg_t msg;
    zmq_msg_init (&msg);
    while (-1 != zmq_msg_recv (&msg, client, ZMQ_DONTWAIT)) {
        zmq_msg_close (&msg);
        zmq_msg_init (&msg);
    }

    close (server_accept);
    close (server);

    test_context_socket_close_zero_linger (client);
    teardown_test_context ();

    return 0;
}

#ifndef ZMQ_USE_FUZZING_ENGINE
void test_connect_ws_fuzzer ()
{
    uint8_t **data;
    size_t *len, num_cases = 0;
    if (fuzzer_corpus_encode (
          "tests/libzmq-fuzz-corpora/test_connect_ws_fuzzer_seed_corpus", &data,
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
    RUN_TEST (test_connect_ws_fuzzer);

    return UNITY_END ();
}
#endif
