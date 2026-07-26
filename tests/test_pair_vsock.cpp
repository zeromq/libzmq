/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string>
#include <sstream>
#include "sys/socket.h"
#include "linux/vm_sockets.h"
#include <sys/ioctl.h>
#include <fcntl.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_pair_vsock ()
{
    if (is_vsock_available () == 0) {
        TEST_IGNORE_MESSAGE ("vsock environnement not available");
    }

    std::stringstream s;
    s << "vsock://@:5562";
    std::string endpoint = s.str ();

    void *sb = test_context_socket (ZMQ_PAIR);
    int rc = zmq_bind (sb, endpoint.c_str ());
    if (rc < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
        TEST_IGNORE_MESSAGE ("VSOCK not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);

    void *sc = test_context_socket (ZMQ_PAIR);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint.c_str ()));

    bounce (sb, sc);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_pair_vsock);
    return UNITY_END ();
}
