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
    unsigned int cid;
    int vsock;

    if ((vsock = open("/dev/vsock", O_RDONLY, 0)) < 0 ) {
        printf("open(\"/dev/vsock\", ...): %d\n", errno);
    } else if (ioctl(vsock, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) {
        printf("ioctl(%d, IOCTL_VM_SOCKETS_GET_LOCAL_CID, ...): %d\n",vsock, errno);
    }

    if (vsock >= 0) {
      close(vsock);
    }

    if (cid == VMADDR_CID_ANY)
        TEST_IGNORE_MESSAGE ("vsock environment unavailable, skipping test");

    std::stringstream s;
    s << "vsock://" << cid << ":" << 5561;
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
