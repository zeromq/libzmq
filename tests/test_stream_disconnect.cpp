/*
    Copyright (c) 2007-2017 Contributors as noted in the AUTHORS file

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

static const int SERVER = 0;
static const int CLIENT = 1;

struct test_message_t
{
    int turn;
    const char *text;
};

// NOTE: messages are sent without null terminator.
const test_message_t dialog[] = {
  {CLIENT, "i can haz cheez burger?"},
  {SERVER, "y u no disonnect?"},
  {CLIENT, ""},
};
const int steps = sizeof (dialog) / sizeof (dialog[0]);

bool has_more (void *socket_)
{
    int more = 0;
    size_t more_size = sizeof (more);
    int rc = zmq_getsockopt (socket_, ZMQ_RCVMORE, &more, &more_size);
    if (rc != 0)
        return false;
    return more != 0;
}

void test_stream_disconnect ()
{
    size_t len = MAX_SOCKET_STRING;
    char bind_endpoint[MAX_SOCKET_STRING];
    char connect_endpoint[MAX_SOCKET_STRING];
    void *sockets[2];

    sockets[SERVER] = test_context_socket (ZMQ_STREAM);
    int enabled = 1;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sockets[SERVER], ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sockets[SERVER], "tcp://0.0.0.0:*"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sockets[SERVER], ZMQ_LAST_ENDPOINT, bind_endpoint, &len));

    //  Apparently Windows can't connect to 0.0.0.0. A better fix would be welcome.
#ifdef ZMQ_HAVE_WINDOWS
    sprintf (connect_endpoint, "tcp://127.0.0.1:%s",
             strrchr (bind_endpoint, ':') + 1);
#else
    strcpy (connect_endpoint, bind_endpoint);
#endif

    sockets[CLIENT] = test_context_socket (ZMQ_STREAM);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_setsockopt (
      sockets[CLIENT], ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled)));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (sockets[CLIENT], connect_endpoint));

    // wait for connect notification
    // Server: Grab the 1st frame (peer routing id).
    zmq_msg_t peer_frame;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&peer_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&peer_frame, sockets[SERVER], 0));
    TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&peer_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_frame));
    TEST_ASSERT_TRUE (has_more (sockets[SERVER]));

    // Server: Grab the 2nd frame (actual payload).
    zmq_msg_t data_frame;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&data_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&data_frame, sockets[SERVER], 0));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&data_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));

    // Client: Grab the 1st frame (peer routing id).
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&peer_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&peer_frame, sockets[CLIENT], 0));
    TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&peer_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_frame));
    TEST_ASSERT_TRUE (has_more (sockets[CLIENT]));

    // Client: Grab the 2nd frame (actual payload).
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&data_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_recv (&data_frame, sockets[CLIENT], 0));
    TEST_ASSERT_EQUAL_INT (0, zmq_msg_size (&data_frame));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));

    // Send initial message.
    char blob_data[256];
    size_t blob_size = sizeof (blob_data);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_getsockopt (sockets[CLIENT], ZMQ_ROUTING_ID, blob_data, &blob_size));
    TEST_ASSERT_GREATER_THAN (0, blob_size);
    zmq_msg_t msg;
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init_size (&msg, blob_size));
    memcpy (zmq_msg_data (&msg), blob_data, blob_size);
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_send (&msg, sockets[dialog[0].turn], ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_init_size (&msg, strlen (dialog[0].text)));
    memcpy (zmq_msg_data (&msg), dialog[0].text, strlen (dialog[0].text));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_msg_send (&msg, sockets[dialog[0].turn], ZMQ_SNDMORE));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&msg));

    // TODO: make sure this loop doesn't loop forever if something is wrong
    //       with the test (or the implementation).

    int step = 0;
    while (step < steps) {
        // Wait until something happens.
        zmq_pollitem_t items[] = {
          {sockets[SERVER], 0, ZMQ_POLLIN, 0},
          {sockets[CLIENT], 0, ZMQ_POLLIN, 0},
        };
        TEST_ASSERT_SUCCESS_ERRNO (zmq_poll (items, 2, 100));

        // Check for data received by the server.
        if (items[SERVER].revents & ZMQ_POLLIN) {
            TEST_ASSERT_EQUAL_INT (CLIENT, dialog[step].turn);

            // Grab the 1st frame (peer routing id).
            zmq_msg_t peer_frame;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&peer_frame));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_recv (&peer_frame, sockets[SERVER], 0));
            TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&peer_frame));
            TEST_ASSERT_TRUE (has_more (sockets[SERVER]));

            // Grab the 2nd frame (actual payload).
            zmq_msg_t data_frame;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&data_frame));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_recv (&data_frame, sockets[SERVER], 0));

            // Make sure payload matches what we expect.
            const char *const data =
              static_cast<const char *> (zmq_msg_data (&data_frame));
            const size_t size = zmq_msg_size (&data_frame);
            // 0-length frame is a disconnection notification.  The server
            // should receive it as the last step in the dialogue.
            if (size == 0) {
                ++step;
                TEST_ASSERT_EQUAL_INT (steps, step);
            } else {
                TEST_ASSERT_EQUAL_INT (strlen (dialog[step].text), size);
                TEST_ASSERT_EQUAL_STRING_LEN (dialog[step].text, data, size);

                ++step;

                TEST_ASSERT_LESS_THAN_INT (steps, step);

                // Prepare the response.
                TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_msg_init_size (&data_frame, strlen (dialog[step].text)));
                memcpy (zmq_msg_data (&data_frame), dialog[step].text,
                        zmq_msg_size (&data_frame));

                // Send the response.
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_msg_send (&peer_frame, sockets[SERVER], ZMQ_SNDMORE));
                TEST_ASSERT_SUCCESS_ERRNO (
                  zmq_msg_send (&data_frame, sockets[SERVER], ZMQ_SNDMORE));
            }

            // Release resources.
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_frame));
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));
        }

        // Check for data received by the client.
        if (items[CLIENT].revents & ZMQ_POLLIN) {
            TEST_ASSERT_EQUAL_INT (SERVER, dialog[step].turn);

            // Grab the 1st frame (peer routing id).
            zmq_msg_t peer_frame;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&peer_frame));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_recv (&peer_frame, sockets[CLIENT], 0));
            TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&peer_frame));
            TEST_ASSERT_TRUE (has_more (sockets[CLIENT]));

            // Grab the 2nd frame (actual payload).
            zmq_msg_t data_frame;
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_init (&data_frame));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_recv (&data_frame, sockets[CLIENT], 0));
            TEST_ASSERT_GREATER_THAN_INT (0, zmq_msg_size (&data_frame));

            // Make sure payload matches what we expect.
            const char *const data =
              static_cast<const char *> (zmq_msg_data (&data_frame));
            const size_t size = zmq_msg_size (&data_frame);
            TEST_ASSERT_EQUAL_INT (strlen (dialog[step].text), size);
            TEST_ASSERT_EQUAL_STRING_LEN (dialog[step].text, data, size);

            ++step;

            // Prepare the response (next line in the dialog).
            TEST_ASSERT_LESS_THAN_INT (steps, step);
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_init_size (&data_frame, strlen (dialog[step].text)));
            memcpy (zmq_msg_data (&data_frame), dialog[step].text,
                    zmq_msg_size (&data_frame));

            // Send the response.
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_send (&peer_frame, sockets[CLIENT], ZMQ_SNDMORE));
            TEST_ASSERT_SUCCESS_ERRNO (
              zmq_msg_send (&data_frame, sockets[CLIENT], ZMQ_SNDMORE));

            // Release resources.
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&peer_frame));
            TEST_ASSERT_SUCCESS_ERRNO (zmq_msg_close (&data_frame));
        }
    }
    TEST_ASSERT_EQUAL_INT (steps, step);
    test_context_socket_close (sockets[CLIENT]);
    test_context_socket_close (sockets[SERVER]);
}

int main (int, char **)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_stream_disconnect);
    return UNITY_END ();
}
