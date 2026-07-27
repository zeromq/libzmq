/* SPDX-License-Identifier: MPL-2.0 */

#include "../tests/testutil.hpp"

//  On Windows testutil.hpp maps close () to closesocket ().
//  Undo this so it doesn't rewrite zmq::msg_t::close in other headers.
#ifdef close
#undef close
#endif

#include <atomic_counter.hpp>
#include <dbuffer.hpp>
#include <msg.hpp>
#include <thread.hpp>

#include <unity.h>

void setUp ()
{
}
void tearDown ()
{
}

//  All test messages share one payload buffer.
//  Ownership is tracked per message using the hint field, which points at
//  a counter for how many times the content was released.
static char shared_payload[129];

static void count_free (void *data_, void *hint_)
{
    LIBZMQ_UNUSED (data_);
    ++*static_cast<int *> (hint_);
}

//  Writes a message owning 'shared_payload' into the dbuffer and gives up
//  ownership, the way pipe writers do. 'freed_' is incremented when the
//  dbuffer releases the message content.
static void write_counted_msg (zmq::dbuffer_t<zmq::msg_t> &buf_, int *freed_)
{
    zmq::msg_t msg;
    TEST_ASSERT_EQUAL_INT (0,
                           msg.init_data (shared_payload, sizeof shared_payload,
                                          count_free, freed_));
    buf_.write (msg);
    TEST_ASSERT_EQUAL_INT (0, msg.init ());
}

void test_create ()
{
    zmq::dbuffer_t<zmq::msg_t> buf;
    TEST_ASSERT_FALSE (buf.check_read ());
}

void test_read_empty ()
{
    zmq::dbuffer_t<zmq::msg_t> buf;
    zmq::msg_t msg;
    TEST_ASSERT_EQUAL_INT (0, msg.init ());
    TEST_ASSERT_FALSE (buf.read (&msg));
    TEST_ASSERT_EQUAL_INT (0, msg.close ());
}

//  Uncontended conflation.
//  Second write should replace the first message and release its content.
//  The reader must only observe the second message.
void test_conflation_releases_overwritten_message ()
{
    int freed_first = 0, freed_second = 0;

    zmq::dbuffer_t<zmq::msg_t> buf;
    write_counted_msg (buf, &freed_first);
    write_counted_msg (buf, &freed_second);
    TEST_ASSERT_EQUAL_INT (1, freed_first);
    TEST_ASSERT_EQUAL_INT (0, freed_second);

    zmq::msg_t msg;
    TEST_ASSERT_EQUAL_INT (0, msg.init ());
    TEST_ASSERT_TRUE (buf.read (&msg));
    TEST_ASSERT_EQUAL_INT (sizeof shared_payload, msg.size ());
    TEST_ASSERT_EQUAL_INT (0, msg.close ());
    TEST_ASSERT_EQUAL_INT (1, freed_second);

    TEST_ASSERT_FALSE (buf.read (&msg));
}

//  Helpers for parking a reader inside probe (), holding the dbuffer lock.
//  This allows deterministically causing writes to fail try_lock.
static zmq::atomic_counter_t probe_entered;
static zmq::atomic_counter_t probe_release;

static bool blocking_probe_fn (const zmq::msg_t &)
{
    probe_entered.add (1);
    while (probe_release.get () == 0)
        msleep (1);
    return true;
}

static void probe_thread_fn (void *arg_)
{
    static_cast<zmq::dbuffer_t<zmq::msg_t> *> (arg_)->probe (blocking_probe_fn);
}

//  A write to a dbuffer locked by a reader stores the msg in the _back slot.
//  Subsequent writes must release that message instead of overwriting.
//  Previously, this would leak one message per reader/writer collision
//  on sockets with ZMQ_CONFLATE set.
void test_write_while_reader_busy_does_not_leak ()
{
    int freed_first = 0, freed_second = 0, freed_third = 0;

    {
        zmq::dbuffer_t<zmq::msg_t> buf;

        probe_entered.set (0);
        probe_release.set (0);
        zmq::thread_t reader;
        reader.start (probe_thread_fn, &buf, "dbuffer_probe");
        while (probe_entered.get () == 0)
            msleep (1);

        //  The reader now sits inside probe () holding the lock.
        //  Both writes fail try_lock, and the second overwrites _back.
        write_counted_msg (buf, &freed_first);
        write_counted_msg (buf, &freed_second);
        TEST_ASSERT_EQUAL_INT (1, freed_first);
        TEST_ASSERT_EQUAL_INT (0, freed_second);

        probe_release.add (1);
        reader.stop ();

        //  With the reader gone this write swaps successfully.
        //  It must still release the message stored by the failed swap.
        write_counted_msg (buf, &freed_third);
        TEST_ASSERT_EQUAL_INT (1, freed_second);

        zmq::msg_t msg;
        TEST_ASSERT_EQUAL_INT (0, msg.init ());
        TEST_ASSERT_TRUE (buf.read (&msg));
        TEST_ASSERT_EQUAL_INT (0, msg.close ());
        TEST_ASSERT_EQUAL_INT (1, freed_third);
    }

    //  Destruction must not double-release anything.
    TEST_ASSERT_EQUAL_INT (1, freed_first);
    TEST_ASSERT_EQUAL_INT (1, freed_second);
    TEST_ASSERT_EQUAL_INT (1, freed_third);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_create);
    RUN_TEST (test_read_empty);
    RUN_TEST (test_conflation_releases_overwritten_message);
    RUN_TEST (test_write_while_reader_busy_does_not_leak);

    return UNITY_END ();
}
