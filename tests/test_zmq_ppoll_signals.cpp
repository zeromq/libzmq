/* SPDX-License-Identifier: MPL-2.0 */

// author: E. G. Patrick Bos, Netherlands eScience Center, 2021

#include "testutil.hpp"
#include "testutil_unity.hpp"

#include <string.h> // memset
// types.h and wait.h for waitpid:
#include <sys/types.h>
#include <sys/wait.h>

static bool sigterm_received = false;

void handle_sigterm (int /*signum*/)
{
    sigterm_received = true;
}

void recv_string_expect_success_or_eagain (void *socket_,
                                           const char *str_,
                                           int flags_)
{
    const size_t len = str_ ? strlen (str_) : 0;
    char buffer[255];
    TEST_ASSERT_LESS_OR_EQUAL_MESSAGE (sizeof (buffer), len,
                                       "recv_string_expect_success cannot be "
                                       "used for strings longer than 255 "
                                       "characters");

    const int rc = zmq_recv (socket_, buffer, sizeof (buffer), flags_);
    if (rc < 0) {
        if (errno == EAGAIN) {
            printf ("got EAGAIN\n");
            return;
        } else {
            TEST_ASSERT_SUCCESS_ERRNO (rc);
        }
    } else {
        TEST_ASSERT_EQUAL_INT ((int) len, rc);
        if (str_)
            TEST_ASSERT_EQUAL_STRING_LEN (str_, buffer, len);
    }
}

void test_ppoll_signals ()
{
#ifdef ZMQ_HAVE_PPOLL
    size_t len = MAX_SOCKET_STRING;
    char my_endpoint[MAX_SOCKET_STRING];
    pid_t child_pid;

    /* Get a random TCP port first */
    setup_test_context ();
    void *sb = test_context_socket (ZMQ_REP);
    bind_loopback (sb, 0, my_endpoint, len);
    test_context_socket_close (sb);
    teardown_test_context ();

    do {
        child_pid = fork ();
    } while (child_pid == -1); // retry if fork fails

    if (child_pid > 0) { // parent
        setup_test_context ();
        void *socket = test_context_socket (ZMQ_REQ);
        // to make sure we don't hang when the child has already exited at the end, we set a receive timeout of five seconds
        int recv_timeout = 5000;
        TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
          socket, ZMQ_RCVTIMEO, &recv_timeout, sizeof (recv_timeout)));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (socket, my_endpoint));
        // bind is on the master process to avoid zombie children to hold on to binds

        // first send a test message to check whether the signal mask is setup in the child process
        send_string_expect_success (socket, "breaker breaker", 0);
        recv_string_expect_success (socket, "one-niner", 0);

        // then send the signal
        kill (child_pid, SIGTERM);

        // for good measure, and to make sure everything went as expected, close off with another handshake, which will trigger the second poll call on the other side
        send_string_expect_success (socket, "breaker breaker", 0);
        // in case the 1 second sleep was not enough on the child side, we are also fine with an EAGAIN here
        recv_string_expect_success_or_eagain (socket, "one-niner", 0);

        // finish
        test_context_socket_close (socket);
        teardown_test_context ();

        // wait for child
        int status = 0;
        pid_t pid;
        do {
            pid = waitpid (child_pid, &status, 0);
        } while (-1 == pid
                 && EINTR == errno); // retry on interrupted system call

        if (0 != status) {
            if (WIFEXITED (status)) {
                printf ("exited, status=%d\n", WEXITSTATUS (status));
            } else if (WIFSIGNALED (status)) {
                printf ("killed by signal %d\n", WTERMSIG (status));
            } else if (WIFSTOPPED (status)) {
                printf ("stopped by signal %d\n", WSTOPSIG (status));
            } else if (WIFCONTINUED (status)) {
                printf ("continued\n");
            }
        }

        if (-1 == pid) {
            printf ("waitpid returned -1, with errno %s\n", strerror (errno));
        }
    } else { // child
        setup_test_context ();
        // set up signal mask and install handler for SIGTERM
        sigset_t sigmask, sigmask_without_sigterm;
        sigemptyset (&sigmask);
        sigaddset (&sigmask, SIGTERM);
        sigprocmask (SIG_BLOCK, &sigmask, &sigmask_without_sigterm);
        struct sigaction sa;
        memset (&sa, '\0', sizeof (sa));
        sa.sa_handler = handle_sigterm;
        TEST_ASSERT_SUCCESS_ERRNO (sigaction (SIGTERM, &sa, NULL));

        void *socket = test_context_socket (ZMQ_REP);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (socket, my_endpoint));

        zmq_pollitem_t pollitems[] = {
          {socket, 0, ZMQ_POLLIN, 0},
        };

        // first receive test message and send back handshake
        recv_string_expect_success (socket, "breaker breaker", 0);
        send_string_expect_success (socket, "one-niner", 0);

        // now start ppolling, which should exit with EINTR because of the SIGTERM
        TEST_ASSERT_FAILURE_ERRNO (
          EINTR, zmq_ppoll (pollitems, 1, -1, &sigmask_without_sigterm));
        TEST_ASSERT_TRUE (sigterm_received);

        // poll again for the final handshake
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_ppoll (pollitems, 1, -1, &sigmask_without_sigterm));
        TEST_ASSERT_BITS_HIGH (ZMQ_POLLIN, pollitems[0].revents);
        // receive and send back handshake
        recv_string_expect_success (socket, "breaker breaker", 0);
        send_string_expect_success (socket, "one-niner", 0);

        // finish
        // wait before closing socket, so that parent has time to receive
        sleep (1);
        test_context_socket_close (socket);
        teardown_test_context ();
        _Exit (0);
    }
#else
    TEST_IGNORE_MESSAGE ("libzmq without zmq_ppoll, ignoring test");
#endif // ZMQ_HAVE_PPOLL
}

// We note that using zmq_poll instead of zmq_ppoll in the test above, while
// also not using the sigmask, will fail most of the time, because it is
// impossible to predict during which call the signal will be handled. Of
// course, every call could be surrounded with an EINTR check and a subsequent
// check of sigterm_received's value, but even then a race condition can occur,
// see the explanation given here: https://250bpm.com/blog:12/

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_ppoll_signals);
    return UNITY_END ();
}
