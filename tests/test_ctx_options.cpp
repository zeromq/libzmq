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

#include <limits>
#include "testutil.hpp"

#define WAIT_FOR_BACKGROUND_THREAD_INSPECTION (0)

#ifdef ZMQ_HAVE_LINUX
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h> // for sleep()

#define TEST_POLICY                                                            \
    (SCHED_OTHER) // NOTE: SCHED_OTHER is the default Linux scheduler

bool is_allowed_to_raise_priority ()
{
    // NOTE1: if setrlimit() fails with EPERM, this means that current user has not enough permissions.
    // NOTE2: even for privileged users (e.g., root) getrlimit() would usually return 0 as nice limit; the only way to
    //        discover if the user is able to increase the nice value is to actually try to change the rlimit:
    struct rlimit rlim;
    rlim.rlim_cur = 40;
    rlim.rlim_max = 40;
    if (setrlimit (RLIMIT_NICE, &rlim) == 0) {
        // rlim_cur == 40 means that this process is allowed to set a nice value of -20
        if (WAIT_FOR_BACKGROUND_THREAD_INSPECTION)
            printf ("This process has enough permissions to raise ZMQ "
                    "background thread priority!\n");
        return true;
    }

    if (WAIT_FOR_BACKGROUND_THREAD_INSPECTION)
        printf ("This process has NOT enough permissions to raise ZMQ "
                "background thread priority.\n");
    return false;
}

#else

#define TEST_POLICY (0)

bool is_allowed_to_raise_priority ()
{
    return false;
}

#endif


void test_ctx_thread_opts (void *ctx_)
{
    int rc;

    // verify that setting negative values (e.g., default values) fail:
    rc =
      zmq_ctx_set (ctx_, ZMQ_THREAD_SCHED_POLICY, ZMQ_THREAD_SCHED_POLICY_DFLT);
    assert (rc == -1 && errno == EINVAL);
    rc = zmq_ctx_set (ctx_, ZMQ_THREAD_PRIORITY, ZMQ_THREAD_PRIORITY_DFLT);
    assert (rc == -1 && errno == EINVAL);


    // test scheduling policy:

    // set context options that alter the background thread CPU scheduling/affinity settings;
    // as of ZMQ 4.2.3 this has an effect only on POSIX systems (nothing happens on Windows, but still it should return success):
    rc = zmq_ctx_set (ctx_, ZMQ_THREAD_SCHED_POLICY, TEST_POLICY);
    assert (rc == 0);
    rc = zmq_ctx_get (ctx_, ZMQ_THREAD_SCHED_POLICY);
    assert (rc == TEST_POLICY);


    // test priority:

    // in theory SCHED_OTHER supports only the static priority 0 but quoting the docs
    //     http://man7.org/linux/man-pages/man7/sched.7.html
    // "The thread to run is chosen from the static priority 0 list based on
    // a dynamic priority that is determined only inside this list.  The
    // dynamic priority is based on the nice value [...]
    // The nice value can be modified using nice(2), setpriority(2), or sched_setattr(2)."
    // ZMQ will internally use nice(2) to set the nice value when using SCHED_OTHER.
    // However changing the nice value of a process requires appropriate permissions...
    // check that the current effective user is able to do that:
    if (is_allowed_to_raise_priority ()) {
        rc = zmq_ctx_set (
          ctx_, ZMQ_THREAD_PRIORITY,
          1 /* any positive value different than the default will be ok */);
        assert (rc == 0);
    }


#ifdef ZMQ_THREAD_AFFINITY_CPU_ADD
    // test affinity:

    // this should result in background threads being placed only on the
    // first CPU available on this system; try experimenting with other values
    // (e.g., 5 to use CPU index 5) and use "top -H" or "taskset -pc" to see the result

    int cpus_add[] = {0, 1};
    for (unsigned int idx = 0; idx < sizeof (cpus_add) / sizeof (cpus_add[0]);
         idx++) {
        rc = zmq_ctx_set (ctx_, ZMQ_THREAD_AFFINITY_CPU_ADD, cpus_add[idx]);
        assert (rc == 0);
    }

    // you can also remove CPUs from list of affinities:
    int cpus_remove[] = {1};
    for (unsigned int idx = 0;
         idx < sizeof (cpus_remove) / sizeof (cpus_remove[0]); idx++) {
        rc =
          zmq_ctx_set (ctx_, ZMQ_THREAD_AFFINITY_CPU_REMOVE, cpus_remove[idx]);
        assert (rc == 0);
    }
#endif


#ifdef ZMQ_THREAD_NAME_PREFIX
    // test thread name prefix:

    rc = zmq_ctx_set (ctx_, ZMQ_THREAD_NAME_PREFIX, 1234);
    assert (rc == 0);
    rc = zmq_ctx_get (ctx_, ZMQ_THREAD_NAME_PREFIX);
    assert (rc == 1234);
#endif
}

void test_ctx_zero_copy (void *ctx_)
{
#ifdef ZMQ_ZERO_COPY_RECV
    int zero_copy;
    // Default value is 1.
    zero_copy = zmq_ctx_get (ctx_, ZMQ_ZERO_COPY_RECV);
    assert (zero_copy == 1);

    // Test we can set it to 0.
    assert (0 == zmq_ctx_set (ctx_, ZMQ_ZERO_COPY_RECV, 0));
    zero_copy = zmq_ctx_get (ctx_, ZMQ_ZERO_COPY_RECV);
    assert (zero_copy == 0);

    // Create a TCP socket pair using the context and test that messages can be
    // received. Note that inproc sockets cannot be used for this test.
    void *pull = zmq_socket (ctx_, ZMQ_PULL);
    assert (0 == zmq_bind (pull, "tcp://127.0.0.1:*"));

    void *push = zmq_socket (ctx_, ZMQ_PUSH);
    size_t endpoint_len = MAX_SOCKET_STRING;
    char endpoint[MAX_SOCKET_STRING];
    assert (
      0 == zmq_getsockopt (pull, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len));
    assert (0 == zmq_connect (push, endpoint));

    const char *small_str = "abcd";
    const char *large_str =
      "01234567890123456789012345678901234567890123456789";

    assert (4 == zmq_send (push, (void *) small_str, 4, 0));
    assert (40 == zmq_send (push, (void *) large_str, 40, 0));

    zmq_msg_t small_msg, large_msg;
    zmq_msg_init (&small_msg);
    zmq_msg_init (&large_msg);
    assert (4 == zmq_msg_recv (&small_msg, pull, 0));
    assert (40 == zmq_msg_recv (&large_msg, pull, 0));
    assert (!strncmp (small_str, (const char *) zmq_msg_data (&small_msg), 4));
    assert (!strncmp (large_str, (const char *) zmq_msg_data (&large_msg), 40));

    // Clean up.
    assert (0 == zmq_close (push));
    assert (0 == zmq_close (pull));
    assert (0 == zmq_msg_close (&small_msg));
    assert (0 == zmq_msg_close (&large_msg));
    assert (0 == zmq_ctx_set (ctx_, ZMQ_ZERO_COPY_RECV, 1));
    zero_copy = zmq_ctx_get (ctx_, ZMQ_ZERO_COPY_RECV);
    assert (zero_copy == 1);
#endif
}

int main (void)
{
    setup_test_environment ();
    int rc;

    //  Set up our context and sockets
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    assert (zmq_ctx_get (ctx, ZMQ_MAX_SOCKETS) == ZMQ_MAX_SOCKETS_DFLT);
#if defined(ZMQ_USE_SELECT)
    assert (zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT) == FD_SETSIZE - 1);
#elif defined(ZMQ_USE_POLL) || defined(ZMQ_USE_EPOLL)                          \
  || defined(ZMQ_USE_DEVPOLL) || defined(ZMQ_USE_KQUEUE)
    assert (zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT) == 65535);
#endif
    assert (zmq_ctx_get (ctx, ZMQ_IO_THREADS) == ZMQ_IO_THREADS_DFLT);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 0);
#if defined(ZMQ_MSG_T_SIZE)
    assert (zmq_ctx_get (ctx, ZMQ_MSG_T_SIZE) == sizeof (zmq_msg_t));
#endif

    rc = zmq_ctx_set (ctx, ZMQ_IPV6, true);
    assert (zmq_ctx_get (ctx, ZMQ_IPV6) == 1);

    test_ctx_thread_opts (ctx);
    test_ctx_zero_copy (ctx);

    void *router = zmq_socket (ctx, ZMQ_ROUTER);
    int value;
    size_t optsize = sizeof (int);
    rc = zmq_getsockopt (router, ZMQ_IPV6, &value, &optsize);
    assert (rc == 0);
    assert (value == 1);
    rc = zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize);
    assert (rc == 0);
    assert (value == -1);
    rc = zmq_close (router);
    assert (rc == 0);

#if WAIT_FOR_BACKGROUND_THREAD_INSPECTION
    // this is useful when you want to use an external tool (like top or taskset) to view
    // properties of the background threads
    printf ("Sleeping for 100sec. You can now use 'top -H -p $(pgrep -f "
            "test_ctx_options)' and 'taskset -pc <ZMQ background thread PID>' "
            "to view ZMQ background thread properties.\n");
    sleep (100);
#endif

    rc = zmq_ctx_set (ctx, ZMQ_BLOCKY, false);
    assert (zmq_ctx_get (ctx, ZMQ_BLOCKY) == 0);
    router = zmq_socket (ctx, ZMQ_ROUTER);
    rc = zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize);
    assert (rc == 0);
    assert (value == 0);
    rc = zmq_close (router);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
