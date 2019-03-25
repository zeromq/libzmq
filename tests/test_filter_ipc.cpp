/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#include <unistd.h>
#include <grp.h>

SETUP_TEARDOWN_TESTCONTEXT

static void bounce_fail (void *server_, void *client_)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";
    char buffer[32];

    //  Send message from client to server
    send_string_expect_success (client_, content, ZMQ_SNDMORE);
    send_string_expect_success (client_, content, 0);

    //  Receive message at server side (should not succeed)
    int timeout = SETTLE_TIME;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server_, ZMQ_RCVTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN, zmq_recv (server_, buffer, 32, 0));

    //  Send message from server to client to test other direction
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (server_, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_FAILURE_ERRNO (EAGAIN,
                               zmq_send (server_, content, 32, ZMQ_SNDMORE));
}

template <class T>
static void
run_test (int opt_, T optval_, int expected_error_, int bounce_test_)
{
    void *sb = test_context_socket (ZMQ_DEALER);

    if (opt_) {
        const int rc = zmq_setsockopt (sb, opt_, &optval_, sizeof (optval_));
        if (expected_error_) {
            TEST_ASSERT_FAILURE_ERRNO (expected_error_, rc);
        } else {
            TEST_ASSERT_SUCCESS_ERRNO (rc);
        }
    }

    void *sc = test_context_socket (ZMQ_DEALER);

    // If a test fails, don't hang for too long
    int timeout = 2500;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_RCVTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sb, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_RCVTIMEO, &timeout, sizeof (int)));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (int)));
    int interval = -1;
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sc, ZMQ_RECONNECT_IVL, &interval, sizeof (int)));

    if (bounce_test_) {
        const char *endpoint = "ipc://test_filter_ipc.sock";
        TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, endpoint));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sc, endpoint));

        if (bounce_test_ > 0)
            bounce (sb, sc);
        else
            bounce_fail (sb, sc);
    }

    // TODO only use zero linger when bounce_test_ < 0?
    test_context_socket_close_zero_linger (sc);
    test_context_socket_close_zero_linger (sb);
}

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
gid_t group, supgroup, notgroup;

void init_groups ()
{
    // Get the group and supplemental groups of the process owner
    gid_t groups[100];
    int ngroups = getgroups (100, groups);
    TEST_ASSERT_NOT_EQUAL (-1, ngroups);
    group = getgid ();
    supgroup = group;
    notgroup = group + 1;
    for (int i = 0; i < ngroups; i++) {
        if (supgroup == group && group != groups[i]) {
            if (getgrgid (groups[i]))
                supgroup = groups[i];
        }
        if (notgroup <= groups[i])
            notgroup = groups[i] + 1;
    }
}
#endif

void test_no_filters ()
{
    run_test<int> (0, 0, 0, 1);
}

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
void test_filter_with_process_owner_uid ()
{
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, getuid (), 0, 1);
}
void test_filter_with_possibly_nonexistent_uid ()
{
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, getuid () + 1, 0, -1);
}
void test_filter_with_process_owner_gid ()
{
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, group, 0, 1);
}
void test_filter_with_supplemental_process_owner_gid ()
{
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, supgroup, 0, 1);
}
void test_filter_with_possibly_nonexistent_gid ()
{
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, notgroup, 0, -1);
}
#if defined ZMQ_HAVE_SO_PEERCRED
void test_filter_with_current_process_pid ()
{
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid (), 0, 1);
}
void test_filter_with_possibly_nonexistent_pid ()
{
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid () + 1, 0, -1);
}
#else
void test_filter_with_pid_fails ()
{
    // Setup of PID filter should fail with operation not supported error
    // TODO EINVAL is not ENOTSUP (!)
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid (), EINVAL, 0);
}
#endif
#else
void test_filter_with_zero_uid_fails ()
{
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, 0, EINVAL, 0);
}
void test_filter_with_zero_gid_fails ()
{
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, 0, EINVAL, 0);
}
void test_filter_with_zero_pid_fails ()
{
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, 0, EINVAL, 0);
}
#endif // defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED

int main (void)
{
#if !defined(ZMQ_HAVE_WINDOWS)
    setup_test_environment ();

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    init_groups ();
#endif

    UNITY_BEGIN ();
    RUN_TEST (test_no_filters);
#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    RUN_TEST (test_filter_with_process_owner_uid);
    RUN_TEST (test_filter_with_possibly_nonexistent_uid);
    RUN_TEST (test_filter_with_process_owner_gid);
    RUN_TEST (test_filter_with_supplemental_process_owner_gid);
    RUN_TEST (test_filter_with_possibly_nonexistent_gid);
#if defined ZMQ_HAVE_SO_PEERCRED
    RUN_TEST (test_filter_with_current_process_pid);
    RUN_TEST (test_filter_with_possibly_nonexistent_pid);
#else
    RUN_TEST (test_filter_with_pid_fails);
#endif
#else
    RUN_TEST (test_filter_with_zero_uid_fails);
    RUN_TEST (test_filter_with_zero_gid_fails);
    RUN_TEST (test_filter_with_zero_pid_fails);
#endif // defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    return UNITY_END ();
#else
    return 0;
#endif
}
