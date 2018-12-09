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

#include <unity.h>

void setUp ()
{
}

void tearDown ()
{
}

void test ()
{
    void *counter = zmq_atomic_counter_new ();
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_value (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (2, zmq_atomic_counter_inc (counter));
    TEST_ASSERT_EQUAL_INT (3, zmq_atomic_counter_value (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_dec (counter));
    zmq_atomic_counter_set (counter, 2);
    TEST_ASSERT_EQUAL_INT (1, zmq_atomic_counter_dec (counter));
    TEST_ASSERT_EQUAL_INT (0, zmq_atomic_counter_dec (counter));
    zmq_atomic_counter_destroy (&counter);
}

int main ()
{
    UNITY_BEGIN ();
    RUN_TEST (test);
    return UNITY_END ();
}
