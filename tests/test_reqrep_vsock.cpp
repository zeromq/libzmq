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

void test_reqrep_vsock ()
{
    unsigned int cid = VMADDR_CID_ANY;
    int vsock = -1;

    if ((vsock = open ("/dev/vsock", O_RDONLY, 0)) < 0) {
        TEST_IGNORE_MESSAGE ("failed to open /dev/vsock, skipping test");
    } else if (ioctl (vsock, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) {
        TEST_IGNORE_MESSAGE ("failed to get local cid, skipping test");
    }

    if (vsock >= 0) {
        close (vsock);
    }

    if (cid == VMADDR_CID_ANY) {
        TEST_IGNORE_MESSAGE (
          "vsock_loopback environment unavailable, skipping test");
    }

    std::stringstream s;
    s << "vsock://" << cid << ":" << 5561;
    std::string endpoint = s.str ();

    void *sb = test_context_socket (ZMQ_REP);
    int rc = zmq_bind (sb, endpoint.c_str ());
    if (rc < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
        TEST_IGNORE_MESSAGE ("VSOCK not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint.c_str ()));

    bounce (sb, sc);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

void test_reqrep_vsock_loopback ()
{
    unsigned int cid = VMADDR_CID_ANY;
    int vsock = -1;

    if ((vsock = open ("/dev/vsock", O_RDONLY, 0)) < 0) {
        TEST_IGNORE_MESSAGE ("failed to open /dev/vsock, skipping test");
    } else if (ioctl (vsock, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) {
        TEST_IGNORE_MESSAGE ("failed to get local cid, skipping test");
    }

    if (vsock >= 0) {
        close (vsock);
    }

    if (cid == VMADDR_CID_ANY) {
        TEST_IGNORE_MESSAGE (
          "vsock_loopback environment unavailable, skipping test");
    }

    std::stringstream s;
    s << "vsock://@:5562";
    std::string endpoint = s.str ();

    void *sb = test_context_socket (ZMQ_REP);
    int rc = zmq_bind (sb, endpoint.c_str ());
    if (rc < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
        TEST_IGNORE_MESSAGE ("VSOCK not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);

    void *sc = test_context_socket (ZMQ_REQ);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint.c_str ()));

    bounce (sb, sc);

    char reported[255];
    size_t size = 255;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, reported, &size));
    TEST_ASSERT_EQUAL_STRING ("vsock://1:5562", reported);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_reqrep_vsock);
    RUN_TEST (test_reqrep_vsock_loopback);
    return UNITY_END ();
}
