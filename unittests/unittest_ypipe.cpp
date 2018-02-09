/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

This file is part of 0MQ.

0MQ is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

0MQ is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../tests/testutil.hpp"

#include <ypipe.hpp>

#include <unity.h>

void setUp ()
{
}
void tearDown ()
{
}

void test_create ()
{
    zmq::ypipe_t<int, 1> ypipe;
}

void test_check_read_empty ()
{
    zmq::ypipe_t<int, 1> ypipe;
    TEST_ASSERT_FALSE (ypipe.check_read ());
}

void test_read_empty ()
{
    zmq::ypipe_t<int, 1> ypipe;
    int read_value = -1;
    TEST_ASSERT_FALSE (ypipe.read (&read_value));
    TEST_ASSERT_EQUAL (-1, read_value);
}

void test_write_complete_and_check_read_and_read ()
{
    const int value = 42;
    zmq::ypipe_t<int, 1> ypipe;
    ypipe.write (value, false);
    TEST_ASSERT_FALSE (ypipe.check_read ());
    int read_value = -1;
    TEST_ASSERT_FALSE (ypipe.read (&read_value));
    TEST_ASSERT_EQUAL_INT (-1, read_value);
}

void test_write_complete_and_flush_and_check_read_and_read ()
{
    const int value = 42;
    zmq::ypipe_t<int, 1> ypipe;
    ypipe.write (value, false);
    ypipe.flush ();
    TEST_ASSERT_TRUE (ypipe.check_read ());
    int read_value = -1;
    TEST_ASSERT_TRUE (ypipe.read (&read_value));
    TEST_ASSERT_EQUAL_INT (value, read_value);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_create);
    RUN_TEST (test_check_read_empty);
    RUN_TEST (test_read_empty);
    RUN_TEST (test_write_complete_and_check_read_and_read);
    RUN_TEST (test_write_complete_and_flush_and_check_read_and_read);

    return UNITY_END ();
}
