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

#define __STDC_LIMIT_MACROS // to define SIZE_MAX with older compilers
#include "testutil.hpp"

void handler (int timer_id, void *arg)
{
    (void) timer_id; //  Stop 'unused' compiler warnings
    *((bool *) arg) = true;
}

int sleep_and_execute (void *timers_)
{
    int timeout = zmq_timers_timeout (timers_);

    //  Sleep methods are inaccurate, so we sleep in a loop until time arrived
    while (timeout > 0) {
        msleep (timeout);
        timeout = zmq_timers_timeout (timers_);
    }

    return zmq_timers_execute (timers_);
}

void test_null_timer_pointers ()
{
    void *timers = NULL;

    int rc = zmq_timers_destroy (&timers);
    assert (rc == -1 && errno == EFAULT);

//  TODO this currently triggers an access violation
#if 0
  rc = zmq_timers_destroy (NULL);
  assert (rc == -1 && errno == EFAULT);
#endif

    const size_t dummy_interval = 100;
    const int dummy_timer_id = 1;

    rc = zmq_timers_add (timers, dummy_interval, &handler, NULL);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_add (&timers, dummy_interval, &handler, NULL);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_cancel (timers, dummy_timer_id);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_cancel (&timers, dummy_timer_id);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_set_interval (timers, dummy_timer_id, dummy_interval);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_set_interval (&timers, dummy_timer_id, dummy_interval);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_reset (timers, dummy_timer_id);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_reset (&timers, dummy_timer_id);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_timeout (timers);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_timeout (&timers);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_execute (timers);
    assert (rc == -1 && errno == EFAULT);

    rc = zmq_timers_execute (&timers);
    assert (rc == -1 && errno == EFAULT);
}

void test_corner_cases ()
{
    void *timers = zmq_timers_new ();
    assert (timers);

    const size_t dummy_interval = SIZE_MAX;
    const int dummy_timer_id = 1;

    //  attempt to cancel non-existent timer
    int rc = zmq_timers_cancel (timers, dummy_timer_id);
    assert (rc == -1 && errno == EINVAL);

    //  attempt to set interval of non-existent timer
    rc = zmq_timers_set_interval (timers, dummy_timer_id, dummy_interval);
    assert (rc == -1 && errno == EINVAL);

    //  attempt to reset non-existent timer
    rc = zmq_timers_reset (timers, dummy_timer_id);
    assert (rc == -1 && errno == EINVAL);

    //  attempt to add NULL handler
    rc = zmq_timers_add (timers, dummy_interval, NULL, NULL);
    assert (rc == -1 && errno == EFAULT);

    int timer_id = zmq_timers_add (timers, dummy_interval, handler, NULL);
    assert (timer_id != -1);

    //  attempt to cancel timer twice
    //  TODO should this case really be an error? canceling twice could be allowed
    rc = zmq_timers_cancel (timers, timer_id);
    assert (rc == 0);

    rc = zmq_timers_cancel (timers, timer_id);
    assert (rc == -1 && errno == EINVAL);

    //  timeout without any timers active
    rc = zmq_timers_timeout (timers);
    assert (rc == -1);

    rc = zmq_timers_destroy (&timers);
    assert (rc == 0);
}

int main (void)
{
    setup_test_environment ();

    void *timers = zmq_timers_new ();
    assert (timers);

    bool timer_invoked = false;

    const unsigned long full_timeout = 100;
    void *const stopwatch = zmq_stopwatch_start ();

    int timer_id =
      zmq_timers_add (timers, full_timeout, handler, &timer_invoked);
    assert (timer_id);

    //  Timer should not have been invoked yet
    int rc = zmq_timers_execute (timers);
    assert (rc == 0);

#ifdef ZMQ_BUILD_DRAFT_API
    if (zmq_stopwatch_intermediate (stopwatch) < full_timeout) {
        assert (!timer_invoked);
    }
#endif

    //  Wait half the time and check again
    long timeout = zmq_timers_timeout (timers);
    assert (rc != -1);
    msleep (timeout / 2);
    rc = zmq_timers_execute (timers);
    assert (rc == 0);
#ifdef ZMQ_BUILD_DRAFT_API
    if (zmq_stopwatch_intermediate (stopwatch) < full_timeout) {
        assert (!timer_invoked);
    }
#endif

    // Wait until the end
    rc = sleep_and_execute (timers);
    assert (rc == 0);
    assert (timer_invoked);
    timer_invoked = false;

    //  Wait half the time and check again
    timeout = zmq_timers_timeout (timers);
    assert (rc != -1);
    msleep (timeout / 2);
    rc = zmq_timers_execute (timers);
    assert (rc == 0);
#ifdef ZMQ_BUILD_DRAFT_API
    if (zmq_stopwatch_intermediate (stopwatch) < 2 * full_timeout) {
        assert (!timer_invoked);
    }
#endif

    // Reset timer and wait half of the time left
    rc = zmq_timers_reset (timers, timer_id);
    assert (rc == 0);
    msleep (timeout / 2);
    rc = zmq_timers_execute (timers);
    assert (rc == 0);
    if (zmq_stopwatch_stop (stopwatch) < 2 * full_timeout) {
        assert (!timer_invoked);
    }

    // Wait until the end
    rc = sleep_and_execute (timers);
    assert (rc == 0);
    assert (timer_invoked);
    timer_invoked = false;

    // reschedule
    rc = zmq_timers_set_interval (timers, timer_id, 50);
    assert (rc == 0);
    rc = sleep_and_execute (timers);
    assert (rc == 0);
    assert (timer_invoked);
    timer_invoked = false;

    // cancel timer
    timeout = zmq_timers_timeout (timers);
    assert (rc != -1);
    rc = zmq_timers_cancel (timers, timer_id);
    assert (rc == 0);
    msleep (timeout * 2);
    rc = zmq_timers_execute (timers);
    assert (rc == 0);
    assert (!timer_invoked);

    rc = zmq_timers_destroy (&timers);
    assert (rc == 0);

    test_null_timer_pointers ();
    test_corner_cases ();

    return 0;
}
