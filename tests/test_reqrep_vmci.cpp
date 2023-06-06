/* SPDX-License-Identifier: MPL-2.0 */

#include <string>
#include <sstream>
#include <vmci_sockets.h>

#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

void test_reqrep_vmci ()
{
    unsigned int cid = VMCISock_GetLocalCID ();
    if (cid == VMADDR_CID_ANY)
        TEST_IGNORE_MESSAGE ("VMCI environment unavailable, skipping test");
    std::stringstream s;
    s << "vmci://" << cid << ":" << 5560;
    std::string endpoint = s.str ();

    void *sb = test_context_socket (ZMQ_DEALER);
    int rc = zmq_bind (sb, endpoint.c_str ());
    if (rc < 0 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT))
        TEST_IGNORE_MESSAGE ("VMCI not supported");
    TEST_ASSERT_SUCCESS_ERRNO (rc);

    void *sc = test_context_socket (ZMQ_DEALER);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint.c_str ()));

    bounce (sb, sc);

    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_reqrep_vmci);
    return UNITY_END ();
}
