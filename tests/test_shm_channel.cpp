/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil_unity.hpp"
#include "../src/shm_channel.hpp"
#include "../src/shm_fd.hpp"

#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

void setUp ()
{
}

void tearDown ()
{
}

void test_bidirectional_channel_across_independent_mappings ()
{
    const uint32_t slot_count = 8;
    const size_t payload_capacity = 1024;
    const size_t mapping_size =
      zmq::shm_channel_t::memory_size (slot_count, payload_capacity);
    const int fd = zmq::shm_create_fd (mapping_size);
    TEST_ASSERT_GREATER_OR_EQUAL (0, fd);
    void *const server_mapping = zmq::shm_map_fd (fd, mapping_size);
    TEST_ASSERT_NOT_EQUAL (MAP_FAILED, server_mapping);
    TEST_ASSERT_EQUAL_INT (
      0, zmq::shm_channel_t::initialize (server_mapping, mapping_size,
                                         slot_count, payload_capacity));

    int sockets[2];
    TEST_ASSERT_EQUAL_INT (0, socketpair (AF_UNIX, SOCK_STREAM, 0, sockets));
    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        close (sockets[0]);
        close (fd);
        munmap (server_mapping, mapping_size);
        int received_fd = -1;
        size_t received_size = 0;
        assert (zmq::shm_recv_fd (sockets[1], &received_fd, &received_size)
                == 0);
        void *const client_mapping =
          zmq::shm_map_fd (received_fd, received_size);
        assert (client_mapping != MAP_FAILED);
        zmq::shm_channel_t channel (client_mapping, received_size, false);
        assert (channel.valid ());

        const void *data = NULL;
        size_t size = 0;
        unsigned char flags = 0;
        while (!channel.try_receive (0, &data, &size, &flags)) {
        }
        assert (size == 4 && memcmp (data, "ping", 4) == 0 && flags == 3);
        channel.release_receive (0);

        void *payload = NULL;
        while (!payload)
            payload = channel.try_reserve_send (0, 4, 7);
        memcpy (payload, "pong", 4);
        channel.publish_send (0);
        munmap (client_mapping, received_size);
        close (received_fd);
        close (sockets[1]);
        _exit (0);
    }

    close (sockets[1]);
    TEST_ASSERT_EQUAL_INT (0, zmq::shm_send_fd (sockets[0], fd, mapping_size));
    zmq::shm_channel_t channel (server_mapping, mapping_size, true);
    TEST_ASSERT_TRUE (channel.valid ());
    void *payload = NULL;
    while (!payload)
        payload = channel.try_reserve_send (0, 4, 3);
    memcpy (payload, "ping", 4);
    channel.publish_send (0);

    const void *data = NULL;
    size_t size = 0;
    unsigned char flags = 0;
    while (!channel.try_receive (0, &data, &size, &flags)) {
    }
    TEST_ASSERT_EQUAL_UINT64 (4, size);
    TEST_ASSERT_EQUAL_MEMORY ("pong", data, 4);
    TEST_ASSERT_EQUAL_UINT8 (7, flags);
    channel.release_receive (0);

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    munmap (server_mapping, mapping_size);
    close (fd);
    close (sockets[0]);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_bidirectional_channel_across_independent_mappings);
    return UNITY_END ();
}
