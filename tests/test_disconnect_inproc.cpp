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

#include <string.h>

SETUP_TEARDOWN_TESTCONTEXT

/// Initialize a zeromq message with a given null-terminated string
#define ZMQ_PREPARE_STRING(msg, data, size)                                    \
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));                           \
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, size + 1));            \
    memcpy (zmq_msg_data (&msg), data, size + 1);

static int publicationsReceived = 0;
static bool isSubscribed = false;

void test_disconnect_inproc ()
{
    void *pub_socket = test_context_socket (ZMQ_XPUB);
    void *sub_socket = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (sub_socket, ZMQ_SUBSCRIBE, "foo", 3));

    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_bind (pub_socket, "inproc://someInProcDescriptor"));

    int more;
    size_t more_size = sizeof (more);

    for (int iteration = 0;; ++iteration) {
        zmq_pollitem_t items[] = {
          {sub_socket, 0, ZMQ_POLLIN, 0}, // read publications
          {pub_socket, 0, ZMQ_POLLIN, 0}, // read subscriptions
        };
        int rc = zmq_poll (items, 2, 100);

        if (items[1].revents & ZMQ_POLLIN) {
            for (more = 1; more;) {
                zmq_msg_t msg;
                zmq_msg_init (&msg);
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, pub_socket, 0));
                char *buffer = (char *) zmq_msg_data (&msg);

                if (buffer[0] == 0) {
                    TEST_ASSERT_TRUE (isSubscribed);
                    isSubscribed = false;
                } else {
                    TEST_ASSERT_FALSE (isSubscribed);
                    isSubscribed = true;
                }

                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_getsockopt (pub_socket, ZMQ_RCVMORE, &more, &more_size));
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
            }
        }

        if (items[0].revents & ZMQ_POLLIN) {
            more = 1;
            for (more = 1; more;) {
                zmq_msg_t msg;
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&msg));
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&msg, sub_socket, 0));
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_getsockopt (sub_socket, ZMQ_RCVMORE, &more, &more_size));
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
            }
            publicationsReceived++;
        }
        if (iteration == 1) {
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_connect (sub_socket, "inproc://someInProcDescriptor"));
            msleep (SETTLE_TIME);
        }
        if (iteration == 4) {
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_disconnect (sub_socket, "inproc://someInProcDescriptor"));
        }
        if (iteration > 4 && rc == 0)
            break;

        zmq_msg_t channel_envlp;
        ZMQ_PREPARE_STRING (channel_envlp, "foo", 3);
        TEST_ASSERT_SUCCESS_ERRNO (
          zmq_msg_send (&channel_envlp, pub_socket, ZMQ_SNDMORE));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&channel_envlp));

        zmq_msg_t message;
        ZMQ_PREPARE_STRING (message, "this is foo!", 12);
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_send (&message, pub_socket, 0));
        TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&message));
    }
    TEST_ASSERT_EQUAL_INT (3, publicationsReceived);
    TEST_ASSERT_FALSE (isSubscribed);

    test_context_socket_close (pub_socket);
    test_context_socket_close (sub_socket);
}

int main (int, char **)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_disconnect_inproc);
    return UNITY_END ();
}
