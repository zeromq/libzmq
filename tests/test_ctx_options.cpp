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
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

#define WAIT_FOR_BACKGROUND_THREAD_INSPECTION (0)

#ifdef ZMQ_HAVE_LINUX
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h> // for sleep()
#include <sched.h>

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


void test_ctx_thread_opts ()
{
    // verify that setting negative values (e.g., default values) fail:
    TEST_ASSERT_FAILURE_ERRNO (
      EINVAL, zmq_ctx_set (get_test_context (), ZMQ_THREAD_SCHED_POLICY,
                           ZMQ_THREAD_SCHED_POLICY_DFLT));
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, zmq_ctx_set (get_test_context (),
                                                    ZMQ_THREAD_PRIORITY,
                                                    ZMQ_THREAD_PRIORITY_DFLT));


    // test scheduling policy:

    // set context options that alter the background thread CPU scheduling/affinity settings;
    // as of ZMQ 4.2.3 this has an effect only on POSIX systems (nothing happens on Windows, but still it should return success):
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_THREAD_SCHED_POLICY, TEST_POLICY));
    TEST_ASSERT_EQUAL_INT (
      TEST_POLICY, zmq_ctx_get (get_test_context (), ZMQ_THREAD_SCHED_POLICY));

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
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (
          get_test_context (), ZMQ_THREAD_PRIORITY,
          1 /* any positive value different than the default will be ok */));
    }


    // test affinity:

    // this should result in background threads being placed only on the
    // first CPU available on this system; try experimenting with other values
    // (e.g., 5 to use CPU index 5) and use "top -H" or "taskset -pc" to see the result

    int cpus_add[] = {0, 1};
    for (unsigned int idx = 0; idx < sizeof (cpus_add) / sizeof (cpus_add[0]);
         idx++) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (
          get_test_context (), ZMQ_THREAD_AFFINITY_CPU_ADD, cpus_add[idx]));
    }

    // you can also remove CPUs from list of affinities:
    int cpus_remove[] = {1};
    for (unsigned int idx = 0;
         idx < sizeof (cpus_remove) / sizeof (cpus_remove[0]); idx++) {
        TEST_ASSERT_SUCCESS_ERRNO (zmq_ctx_set (get_test_context (),
                                                ZMQ_THREAD_AFFINITY_CPU_REMOVE,
                                                cpus_remove[idx]));
    }


    // test INTEGER thread name prefix:

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_THREAD_NAME_PREFIX, 1234));
    TEST_ASSERT_EQUAL_INT (
      1234, zmq_ctx_get (get_test_context (), ZMQ_THREAD_NAME_PREFIX));

#ifdef ZMQ_BUILD_DRAFT_API
    // test STRING thread name prefix:

    const char prefix[] = "MyPrefix9012345"; // max len is 16 chars

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set_ext (get_test_context (), ZMQ_THREAD_NAME_PREFIX, prefix,
                       sizeof (prefix) / sizeof (char)));

    char buf[16];
    size_t buflen = sizeof (buf) / sizeof (char);
    zmq_ctx_get_ext (get_test_context (), ZMQ_THREAD_NAME_PREFIX, buf, &buflen);
    TEST_ASSERT_EQUAL_STRING (prefix, buf);
#endif
}

void test_ctx_zero_copy ()
{
#ifdef ZMQ_ZERO_COPY_RECV
    int zero_copy;
    // Default value is 1.
    zero_copy = zmq_ctx_get (get_test_context (), ZMQ_ZERO_COPY_RECV);
    TEST_ASSERT_EQUAL_INT (1, zero_copy);

    // Test we can set it to 0.
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_ZERO_COPY_RECV, 0));
    zero_copy = zmq_ctx_get (get_test_context (), ZMQ_ZERO_COPY_RECV);
    TEST_ASSERT_EQUAL_INT (0, zero_copy);

    // Create a TCP socket pair using the context and test that messages can be
    // received. Note that inproc sockets cannot be used for this test.
    void *pull = zmq_socket (get_test_context (), ZMQ_PULL);
    char endpoint[MAX_SOCKET_STRING];
    bind_loopback_ipv4 (pull, endpoint, sizeof endpoint);

    void *push = zmq_socket (get_test_context (), ZMQ_PUSH);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (push, endpoint));

    const char *small_str = "abcd";
    const char *large_str =
      "01234567890123456789012345678901234567890123456789";

    send_string_expect_success (push, small_str, 0);
    send_string_expect_success (push, large_str, 0);

    recv_string_expect_success (pull, small_str, 0);
    recv_string_expect_success (pull, large_str, 0);

    // Clean up.
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (push));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_close (pull));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_ZERO_COPY_RECV, 1));
    TEST_ASSERT_EQUAL_INT (
      1, zmq_ctx_get (get_test_context (), ZMQ_ZERO_COPY_RECV));
#endif
}

void test_ctx_option_max_sockets ()
{
    TEST_ASSERT_EQUAL_INT (ZMQ_MAX_SOCKETS_DFLT,
                           zmq_ctx_get (get_test_context (), ZMQ_MAX_SOCKETS));
}

void test_ctx_option_socket_limit ()
{
#if defined(ZMQ_USE_SELECT)
    TEST_ASSERT_EQUAL_INT (FD_SETSIZE - 1, zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT));
#elif defined(ZMQ_USE_POLL) || defined(ZMQ_USE_EPOLL)                          \
  || defined(ZMQ_USE_DEVPOLL) || defined(ZMQ_USE_KQUEUE)
    TEST_ASSERT_EQUAL_INT (65535, zmq_ctx_get (ctx, ZMQ_SOCKET_LIMIT));
#endif
}

void test_ctx_option_io_threads ()
{
    TEST_ASSERT_EQUAL_INT (ZMQ_IO_THREADS_DFLT,
                           zmq_ctx_get (get_test_context (), ZMQ_IO_THREADS));
}

void test_ctx_option_ipv6 ()
{
    TEST_ASSERT_EQUAL_INT (0, zmq_ctx_get (get_test_context (), ZMQ_IPV6));
}

void test_ctx_option_msg_t_size ()
{
#if defined(ZMQ_MSG_T_SIZE)
    TEST_ASSERT_EQUAL_INT (sizeof (zmq_msg_t),
                           zmq_ctx_get (get_test_context (), ZMQ_MSG_T_SIZE));
#endif
}

void test_ctx_option_ipv6_set ()
{
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_IPV6, true));
    TEST_ASSERT_EQUAL_INT (1, zmq_ctx_get (get_test_context (), ZMQ_IPV6));
}

void test_ctx_option_blocky ()
{
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_IPV6, true));

    void *router = test_context_socket (ZMQ_ROUTER);
    int value;
    size_t optsize = sizeof (int);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_IPV6, &value, &optsize));
    TEST_ASSERT_EQUAL_INT (1, value);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize));
    TEST_ASSERT_EQUAL_INT (-1, value);
    test_context_socket_close (router);

#if WAIT_FOR_BACKGROUND_THREAD_INSPECTION
    // this is useful when you want to use an external tool (like top or taskset) to view
    // properties of the background threads
    printf ("Sleeping for 100sec. You can now use 'top -H -p $(pgrep -f "
            "test_ctx_options)' and 'taskset -pc <ZMQ background thread PID>' "
            "to view ZMQ background thread properties.\n");
    sleep (100);
#endif

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_ctx_set (get_test_context (), ZMQ_BLOCKY, false));
    TEST_ASSERT_EQUAL_INT (0, TEST_ASSERT_SUCCESS_ERRNO ((zmq_ctx_get (
                                get_test_context (), ZMQ_BLOCKY))));
    router = test_context_socket (ZMQ_ROUTER);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (router, ZMQ_LINGER, &value, &optsize));
    TEST_ASSERT_EQUAL_INT (0, value);
    test_context_socket_close (router);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_ctx_option_max_sockets);
    RUN_TEST (test_ctx_option_socket_limit);
    RUN_TEST (test_ctx_option_io_threads);
    RUN_TEST (test_ctx_option_ipv6);
    RUN_TEST (test_ctx_option_msg_t_size);
    RUN_TEST (test_ctx_option_ipv6_set);
    RUN_TEST (test_ctx_thread_opts);
    RUN_TEST (test_ctx_zero_copy);
    RUN_TEST (test_ctx_option_blocky);
    return UNITY_END ();
}
