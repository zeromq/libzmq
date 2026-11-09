/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#if defined ZMQ_HAVE_WINDOWS && defined ZMQ_HAVE_IPC

#include <stdio.h>
#include <stdlib.h>

SETUP_TEARDOWN_TESTCONTEXT

void test_ipc_fallback_with_bad_tmp ()
{
    //  Starting the I/O thread creates the signaler. With an unusable TMP,
    //  creating the AF_UNIX socket pair must fall back to TCP/IP instead
    //  of aborting in the poller with "Bad file descriptor".
    void *sock = test_context_socket (ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sock, "tcp://127.0.0.1:*"));
    test_context_socket_close (sock);
}

static void set_tmp (const wchar_t *value_)
{
    if (_wputenv_s (L"TMP", value_) != 0) {
        fprintf (stderr, "failed to set TMP\n");
        exit (1);
    }
}

int main ()
{
    //  _wtmpnam_s caches the value of TMP on first use, so TMP has to be
    //  made invalid before the first libzmq context/socket is created.
    wchar_t old_tmp[32767] = {0};
    size_t old_tmp_len = 0;
    if (_wgetenv_s (&old_tmp_len, old_tmp, 32767, L"TMP") != 0) {
        fprintf (stderr, "failed to read TMP\n");
        return 1;
    }

    setup_test_environment ();

    set_tmp (L"C:\\zmq-test-no-such-dir\\tmp");

    UNITY_BEGIN ();
    RUN_TEST (test_ipc_fallback_with_bad_tmp);
    const int rc = UNITY_END ();

    set_tmp (old_tmp);

    return rc;
}

#else

int main ()
{
    return 77; //  test skipped: requires Windows and IPC support
}

#endif
