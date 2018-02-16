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

#if defined(min)
#undef min
#endif

#include <generic_mtrie_impl.hpp>

#include <unity.h>

void setUp ()
{
}
void tearDown ()
{
}

int getlen (const zmq::generic_mtrie_t<int>::prefix_t &data)
{
    return strlen (reinterpret_cast<const char *> (data));
}

void test_create ()
{
    zmq::generic_mtrie_t<int> mtrie;
}

void mtrie_count (int *pipe, void *arg)
{
    LIBZMQ_UNUSED (pipe);
    int *count = static_cast<int *> (arg);
    ++*count;
}

void test_check_empty_match_nonempty_data ()
{
    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (0, count);
}

void test_check_empty_match_empty_data ()
{
    zmq::generic_mtrie_t<int> mtrie;

    int count = 0;
    mtrie.match (NULL, 0, mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (0, count);
}

void test_add_single_entry_match_exact ()
{
    int pipe;

    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    bool res = mtrie.add (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_TRUE (res);

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (1, count);
}

void test_add_two_entries_with_same_name_match_exact ()
{
    int pipe_1, pipe_2;

    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    bool res = mtrie.add (test_name, getlen (test_name), &pipe_1);
    TEST_ASSERT_TRUE (res);

    res = mtrie.add (test_name, getlen (test_name), &pipe_2);
    TEST_ASSERT_FALSE (res);

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (2, count);
}

void test_add_two_entries_match_prefix_and_exact ()
{
    int pipe_1, pipe_2;

    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name_prefix =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");
    const zmq::generic_mtrie_t<int>::prefix_t test_name_full =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foobar");

    bool res = mtrie.add (test_name_prefix, getlen (test_name_prefix), &pipe_1);
    TEST_ASSERT_TRUE (res);

    res = mtrie.add (test_name_full, getlen (test_name_full), &pipe_2);
    TEST_ASSERT_TRUE (res);

    int count = 0;
    mtrie.match (test_name_full, getlen (test_name_full), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (2, count);
}

void test_add_rm_single_entry_match_exact ()
{
    int pipe;
    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    mtrie.add (test_name, getlen (test_name), &pipe);
    bool res = mtrie.rm (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_TRUE (res);

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (0, count);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_create);
    RUN_TEST (test_check_empty_match_nonempty_data);
    RUN_TEST (test_check_empty_match_empty_data);
    RUN_TEST (test_add_single_entry_match_exact);
    RUN_TEST (test_add_rm_single_entry_match_exact);
    RUN_TEST (test_add_two_entries_match_prefix_and_exact);
    RUN_TEST (test_add_two_entries_with_same_name_match_exact);

    return UNITY_END ();
}
