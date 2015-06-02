/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

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

#include <string.h>
#include <sys/types.h>

#include <string>
#include <sstream>

#include "testutil.hpp"

static void bounce_fail (void *server, void *client)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";
    char buffer [32];

    //  Send message from client to server
    int rc = zmq_send (client, content, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (client, content, 32, 0);
    assert (rc == 32);

    //  Receive message at server side (should not succeed)
    int timeout = 150;
    rc = zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);

    //  Send message from server to client to test other direction
    rc = zmq_setsockopt (server, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_send (server, content, 32, ZMQ_SNDMORE);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);
}

template <class T>
static void run_test (int opt, T optval, int expected_error, int bounce_test)
{
    int rc;

    void *ctx = zmq_ctx_new ();
    assert (ctx);

    void *sb = zmq_socket (ctx, ZMQ_DEALER);
    assert (sb);

    if (opt) {
        rc = zmq_setsockopt(sb, opt, &optval, sizeof (optval));
        if (expected_error) {
            assert (rc == -1);
            assert (zmq_errno () == expected_error);
        } else {
            assert (rc == 0);
        }
    }

    void *sc = zmq_socket (ctx, ZMQ_DEALER);
    assert (sc);

    // If a test fails, don't hang for too long
    int timeout = 1500;
    rc = zmq_setsockopt (sb, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (sb, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (sc, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (sc, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    int interval = -1;
    rc = zmq_setsockopt (sc, ZMQ_RECONNECT_IVL, &interval, sizeof (int));
    assert (rc == 0);

    if (bounce_test) {
        const char* endpoint = "ipc://test_filter_ipc.sock";
        int rc = zmq_bind (sb, endpoint);
        assert (rc == 0);

        rc = zmq_connect (sc, endpoint);
        assert (rc == 0);

        if (bounce_test > 0)
            bounce (sb, sc);
        else
            bounce_fail (sb, sc);
    }

    close_zero_linger (sc);
    close_zero_linger (sb);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment();

    // No filters
    run_test<int> (0, 0, 0, 1);

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
    // Get the group and supplimental groups of the process owner
    gid_t groups[100];
    int ngroups = getgroups(100, groups);
    assert (ngroups != -1 && ngroups != 0);
    gid_t group = getgid(), supgroup = groups[0], notgroup = groups[ngroups - 1] + 1;
    for (int i = 0; i < ngroups; i++) {
        if (supgroup == group && group != groups[i])
            supgroup = groups[i];
        if (notgroup <= groups[i])
            notgroup = groups[i] + 1;
    }

    // Test filter with UID of process owner
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, getuid(), 0, 1);
    // Test filter with UID of another (possibly non-existent) user
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, getuid() + 1, 0, -1);
    // Test filter with GID of process owner
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, group, 0, 1);
    // Test filter with supplimental group of process owner
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, supgroup, 0, 1);
    // Test filter with GID of another (possibly non-existent) group
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, notgroup, 0, -1);
#   if defined ZMQ_HAVE_SO_PEERCRED
    // Test filter with PID of current process
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid(), 0, 1);
    // Test filter with PID of another (possibly non-existent) process
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid() + 1, 0, -1);
#   else
    // Setup of PID filter should fail with operation not supported error
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, getpid(), EINVAL, 0);
#   endif
#else
    run_test<uid_t> (ZMQ_IPC_FILTER_UID, 0, EINVAL, 0);
    run_test<gid_t> (ZMQ_IPC_FILTER_GID, 0, EINVAL, 0);
    run_test<pid_t> (ZMQ_IPC_FILTER_PID, 0, EINVAL, 0);
#endif // defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED

    return 0 ;
}

