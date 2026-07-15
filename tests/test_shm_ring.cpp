/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil_unity.hpp"
#include "../src/shm_ring.hpp"

#include <assert.h>
#include <new>
#include <string.h>
#include <sys/mman.h>
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

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test_spsc_ring_preserves_cross_process_object_lifetime);
    return UNITY_END ();
}
