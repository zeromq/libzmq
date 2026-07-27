/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil_unity.hpp"
#include "../src/shm_fd.hpp"
#include "../src/shm_ring.hpp"

#include <assert.h>
#include <new>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace
{
struct counters_t
{
    volatile uint32_t constructed;
    volatile uint32_t destroyed;
};

counters_t *counters;

struct message_t
{
    uint64_t sequence;
    unsigned char payload[256];

    message_t (uint64_t sequence_) : sequence (sequence_)
    {
        __atomic_add_fetch (&counters->constructed, 1, __ATOMIC_RELAXED);
        memset (payload, static_cast<unsigned char> (sequence_),
                sizeof payload);
    }

    ~message_t ()
    {
        __atomic_add_fetch (&counters->destroyed, 1, __ATOMIC_RELAXED);
    }
};
}

void setUp ()
{
}

void tearDown ()
{
}

void test_spsc_ring_preserves_cross_process_object_lifetime ()
{
    const uint32_t slot_count = 8;
    const uint64_t message_count = 10000;
    const size_t mapping_size =
      zmq::shm_ring_t::memory_size (slot_count, sizeof (message_t));
    void *const mapping =
      mmap (NULL, mapping_size, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT_NOT_EQUAL (MAP_FAILED, mapping);
    TEST_ASSERT_EQUAL_INT (
      0, zmq::shm_ring_t::initialize (mapping, mapping_size, slot_count,
                                      sizeof (message_t)));

    counters = static_cast<counters_t *> (
      mmap (NULL, sizeof (counters_t), PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    TEST_ASSERT_NOT_EQUAL (MAP_FAILED, counters);
    counters->constructed = 0;
    counters->destroyed = 0;

    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        zmq::shm_ring_t ring (mapping, mapping_size);
        assert (ring.valid ());
        for (uint64_t i = 0; i != message_count; ++i) {
            const message_t *message = NULL;
            while (!message)
                message = static_cast<const message_t *> (
                  ring.try_acquire_read (i));
            assert (message->sequence == i);
            assert (message->payload[0]
                    == static_cast<unsigned char> (i));
            const_cast<message_t *> (message)->~message_t ();
            ring.release_read (i);
        }
        _exit (0);
    }

    zmq::shm_ring_t ring (mapping, mapping_size);
    TEST_ASSERT_TRUE (ring.valid ());
    for (uint64_t i = 0; i != message_count; ++i) {
        void *storage = NULL;
        while (!storage)
            storage = ring.try_acquire_write (i);
        new (storage) message_t (i);
        ring.publish_write (i);
    }

    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    TEST_ASSERT_EQUAL_UINT32 (message_count, counters->constructed);
    TEST_ASSERT_EQUAL_UINT32 (message_count, counters->destroyed);
    TEST_ASSERT_EQUAL_INT (0, munmap (counters, sizeof (counters_t)));
    TEST_ASSERT_EQUAL_INT (0, munmap (mapping, mapping_size));
}

void test_memfd_transfer_supports_independent_mapping ()
{
    const size_t mapping_size = 4096;
    int sockets[2];
    TEST_ASSERT_EQUAL_INT (0, socketpair (AF_UNIX, SOCK_STREAM, 0, sockets));

    const int fd = zmq::shm_create_fd (mapping_size);
    TEST_ASSERT_GREATER_OR_EQUAL (0, fd);
    uint64_t *const parent_mapping = static_cast<uint64_t *> (
      zmq::shm_map_fd (fd, mapping_size));
    TEST_ASSERT_NOT_EQUAL (MAP_FAILED, parent_mapping);
    parent_mapping[0] = UINT64_C (0x1122334455667788);
    parent_mapping[1] = 0;

    const pid_t child = fork ();
    TEST_ASSERT_NOT_EQUAL (-1, child);
    if (child == 0) {
        close (sockets[0]);
        close (fd);
        munmap (parent_mapping, mapping_size);

        int received_fd = -1;
        size_t received_size = 0;
        assert (zmq::shm_recv_fd (sockets[1], &received_fd, &received_size)
                == 0);
        assert (received_size == mapping_size);
        uint64_t *const child_mapping = static_cast<uint64_t *> (
          zmq::shm_map_fd (received_fd, received_size));
        assert (child_mapping != MAP_FAILED);
        assert (child_mapping[0] == UINT64_C (0x1122334455667788));
        child_mapping[1] = UINT64_C (0x8877665544332211);
        munmap (child_mapping, received_size);
        close (received_fd);
        close (sockets[1]);
        _exit (0);
    }

    close (sockets[1]);
    TEST_ASSERT_EQUAL_INT (
      0, zmq::shm_send_fd (sockets[0], fd, mapping_size));
    int status = 0;
    TEST_ASSERT_EQUAL (child, waitpid (child, &status, 0));
    TEST_ASSERT_TRUE (WIFEXITED (status));
    TEST_ASSERT_EQUAL_INT (0, WEXITSTATUS (status));
    TEST_ASSERT_EQUAL_UINT64 (UINT64_C (0x8877665544332211),
                              parent_mapping[1]);
    TEST_ASSERT_EQUAL_INT (0, munmap (parent_mapping, mapping_size));
    close (fd);
    close (sockets[0]);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_spsc_ring_preserves_cross_process_object_lifetime);
    RUN_TEST (test_memfd_transfer_supports_independent_mapping);
    return UNITY_END ();
}
