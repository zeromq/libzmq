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

static const int SERVER = 0;
static const int CLIENT = 1;

struct test_message_t {
    int turn;
    const char * text;
};

// NOTE: messages are sent without null terminator.
const test_message_t dialog [] = {
    {CLIENT, "i can haz cheez burger?"},
    {SERVER, "y u no disonnect?"},
    {CLIENT, ""},
};
const int steps = sizeof(dialog) / sizeof(dialog[0]);

bool has_more (void* socket)
{
    int more = 0;
    size_t more_size = sizeof(more);
    int rc = zmq_getsockopt (socket, ZMQ_RCVMORE, &more, &more_size);
    if (rc != 0)
        return false;
    return more != 0;
}

bool get_identity (void* socket, char* data, size_t* size)
{
    int rc = zmq_getsockopt (socket, ZMQ_IDENTITY, data, size);
    return rc == 0;
}

int main(int, char**)
{
    setup_test_environment();

    void *context = zmq_ctx_new ();
    void *sockets [2];
    int rc = 0;

    sockets [SERVER] = zmq_socket (context, ZMQ_STREAM);
    int enabled = 1;
    rc = zmq_setsockopt (sockets [SERVER], ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled));
    assert (rc == 0);
    rc = zmq_bind (sockets [SERVER], "tcp://0.0.0.0:6666");
    assert (rc == 0);

    sockets [CLIENT] = zmq_socket (context, ZMQ_STREAM);
    rc = zmq_setsockopt (sockets [CLIENT], ZMQ_STREAM_NOTIFY, &enabled, sizeof (enabled));
    assert (rc == 0);
    rc = zmq_connect (sockets [CLIENT], "tcp://localhost:6666");
    assert (rc == 0);

    // wait for connect notification
    // Server: Grab the 1st frame (peer identity).
    zmq_msg_t peer_frame;
    rc = zmq_msg_init (&peer_frame);
    assert (rc == 0);
    rc = zmq_msg_recv (&peer_frame, sockets [SERVER], 0);
    assert (rc != -1);
    assert(zmq_msg_size (&peer_frame) > 0);
    assert (has_more (sockets [SERVER]));
    rc = zmq_msg_close (&peer_frame);
    assert (rc == 0);

    // Server: Grab the 2nd frame (actual payload).
    zmq_msg_t data_frame;
    rc = zmq_msg_init (&data_frame);
    assert (rc == 0);
    rc = zmq_msg_recv (&data_frame, sockets [SERVER], 0);
    assert (rc != -1);
    assert(zmq_msg_size (&data_frame) == 0);
    rc = zmq_msg_close (&data_frame);
    assert (rc == 0);

    // Client: Grab the 1st frame (peer identity).
    rc = zmq_msg_init (&peer_frame);
    assert (rc == 0);
    rc = zmq_msg_recv (&peer_frame, sockets [CLIENT], 0);
    assert (rc != -1);
    assert(zmq_msg_size (&peer_frame) > 0);
    assert (has_more (sockets [CLIENT]));
    rc = zmq_msg_close (&peer_frame);
    assert (rc == 0);

    // Client: Grab the 2nd frame (actual payload).
    rc = zmq_msg_init (&data_frame);
    assert (rc == 0);
    rc = zmq_msg_recv (&data_frame, sockets [CLIENT], 0);
    assert (rc != -1);
    assert(zmq_msg_size (&data_frame) == 0);
    rc = zmq_msg_close (&data_frame);
    assert (rc == 0);

    // Send initial message.
    char blob_data [256];
    size_t blob_size = sizeof(blob_data);
    rc = zmq_getsockopt (sockets [CLIENT], ZMQ_IDENTITY, blob_data, &blob_size);
    assert (rc != -1);
    assert(blob_size > 0);
    zmq_msg_t msg;
    rc = zmq_msg_init_size (&msg, blob_size);
    assert (rc == 0);
    memcpy (zmq_msg_data (&msg), blob_data, blob_size);
    rc = zmq_msg_send (&msg, sockets [dialog [0].turn], ZMQ_SNDMORE);
    assert (rc != -1);
    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    rc = zmq_msg_init_size (&msg, strlen(dialog [0].text));
    assert (rc == 0);
    memcpy (zmq_msg_data (&msg), dialog [0].text, strlen(dialog [0].text));
    rc = zmq_msg_send (&msg, sockets [dialog [0].turn], ZMQ_SNDMORE);
    assert (rc != -1);
    rc = zmq_msg_close (&msg);
    assert (rc == 0);

    // TODO: make sure this loop doesn't loop forever if something is wrong
    //       with the test (or the implementation).

    int step = 0;
    while (step < steps) {
        // Wait until something happens.
        zmq_pollitem_t items [] = {
            { sockets [SERVER], 0, ZMQ_POLLIN, 0 },
            { sockets [CLIENT], 0, ZMQ_POLLIN, 0 },
        };
        int rc = zmq_poll (items, 2, 100);
        assert (rc >= 0);

        // Check for data received by the server.
        if (items [SERVER].revents & ZMQ_POLLIN) {
            assert (dialog [step].turn == CLIENT);

            // Grab the 1st frame (peer identity).
            zmq_msg_t peer_frame;
            rc = zmq_msg_init (&peer_frame);
            assert (rc == 0);
            rc = zmq_msg_recv (&peer_frame, sockets [SERVER], 0);
            assert (rc != -1);
            assert(zmq_msg_size (&peer_frame) > 0);
            assert (has_more (sockets [SERVER]));

            // Grab the 2nd frame (actual payload).
            zmq_msg_t data_frame;
            rc = zmq_msg_init (&data_frame);
            assert (rc == 0);
            rc = zmq_msg_recv (&data_frame, sockets [SERVER], 0);
            assert (rc != -1);

            // Make sure payload matches what we expect.
            const char * const data = (const char*)zmq_msg_data (&data_frame);
            const int size = zmq_msg_size (&data_frame);
            // 0-length frame is a disconnection notification.  The server
            // should receive it as the last step in the dialogue.
            if (size == 0) {
                ++step;
                assert (step == steps);
            }
            else {
                assert ((size_t) size == strlen (dialog [step].text));
                int cmp = memcmp (dialog [step].text, data, size);
                assert (cmp == 0);

                ++step;

                assert (step < steps);

                // Prepare the response.
                rc = zmq_msg_close (&data_frame);
                assert (rc == 0);
                rc = zmq_msg_init_size (&data_frame,
                                        strlen (dialog [step].text));
                assert (rc == 0);
                memcpy (zmq_msg_data (&data_frame), dialog [step].text,
                        zmq_msg_size (&data_frame));

                // Send the response.
                rc = zmq_msg_send (&peer_frame, sockets [SERVER], ZMQ_SNDMORE);
                assert (rc != -1);
                rc = zmq_msg_send (&data_frame, sockets [SERVER], ZMQ_SNDMORE);
                assert (rc != -1);
            }

            // Release resources.
            rc = zmq_msg_close (&peer_frame);
            assert (rc == 0);
            rc = zmq_msg_close (&data_frame);
            assert (rc == 0);
        }

        // Check for data received by the client.
        if (items [CLIENT].revents & ZMQ_POLLIN) {
            assert (dialog [step].turn == SERVER);

            // Grab the 1st frame (peer identity).
            zmq_msg_t peer_frame;
            rc = zmq_msg_init (&peer_frame);
            assert (rc == 0);
            rc = zmq_msg_recv (&peer_frame, sockets [CLIENT], 0);
            assert (rc != -1);
            assert(zmq_msg_size (&peer_frame) > 0);
            assert (has_more (sockets [CLIENT]));

            // Grab the 2nd frame (actual payload).
            zmq_msg_t data_frame;
            rc = zmq_msg_init (&data_frame);
            assert (rc == 0);
            rc = zmq_msg_recv (&data_frame, sockets [CLIENT], 0);
            assert (rc != -1);
            assert(zmq_msg_size (&data_frame) > 0);

            // Make sure payload matches what we expect.
            const char * const data = (const char*)zmq_msg_data (&data_frame);
            const int size = zmq_msg_size (&data_frame);
            assert ((size_t)size == strlen(dialog [step].text));
            int cmp = memcmp(dialog [step].text, data, size);
            assert (cmp == 0);

            ++step;

            // Prepare the response (next line in the dialog).
            assert (step < steps);
            rc = zmq_msg_close (&data_frame);
            assert (rc == 0);
            rc = zmq_msg_init_size (&data_frame, strlen (dialog [step].text));
            assert (rc == 0);
            memcpy (zmq_msg_data (&data_frame), dialog [step].text, zmq_msg_size (&data_frame));

            // Send the response.
            rc = zmq_msg_send (&peer_frame, sockets [CLIENT], ZMQ_SNDMORE);
            assert (rc != -1);
            rc = zmq_msg_send (&data_frame, sockets [CLIENT], ZMQ_SNDMORE);
            assert (rc != -1);

            // Release resources.
            rc = zmq_msg_close (&peer_frame);
            assert (rc == 0);
            rc = zmq_msg_close (&data_frame);
            assert (rc == 0);
        }
    }
    assert (step == steps);
    rc = zmq_close (sockets [CLIENT]);
    assert (rc == 0);
    rc = zmq_close (sockets [SERVER]);
    assert (rc == 0);
    rc = zmq_ctx_term (context);
    assert (rc == 0);
    return 0;
}
