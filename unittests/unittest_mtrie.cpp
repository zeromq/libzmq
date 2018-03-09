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
    return (int) strlen (reinterpret_cast<const char *> (data));
}

void test_create ()
{
    zmq::generic_mtrie_t<int> mtrie;
}

void mtrie_count (int *pipe, int *count)
{
    LIBZMQ_UNUSED (pipe);
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

void test_add_single_entry_twice_match_exact ()
{
    int pipe;

    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    bool res = mtrie.add (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_TRUE (res);

    res = mtrie.add (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_FALSE (res);

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
    zmq::generic_mtrie_t<int>::rm_result res =
      mtrie.rm (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::last_value_removed, res);

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (0, count);
}

void test_rm_nonexistent_0_size_empty ()
{
    int pipe;
    zmq::generic_mtrie_t<int> mtrie;

    zmq::generic_mtrie_t<int>::rm_result res = mtrie.rm (0, 0, &pipe);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::not_found, res);
}

void test_rm_nonexistent_empty ()
{
    int pipe;
    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t test_name =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> ("foo");

    zmq::generic_mtrie_t<int>::rm_result res =
      mtrie.rm (test_name, getlen (test_name), &pipe);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::not_found, res);

    int count = 0;
    mtrie.match (test_name, getlen (test_name), mtrie_count, &count);
    TEST_ASSERT_EQUAL_INT (0, count);
}

void test_add_and_rm_other (const char *add_name, const char *rm_name)
{
    int addpipe, rmpipe;
    zmq::generic_mtrie_t<int> mtrie;
    const zmq::generic_mtrie_t<int>::prefix_t add_name_data =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (add_name);
    const zmq::generic_mtrie_t<int>::prefix_t rm_name_data =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (rm_name);

    mtrie.add (add_name_data, getlen (add_name_data), &addpipe);

    zmq::generic_mtrie_t<int>::rm_result res =
      mtrie.rm (rm_name_data, getlen (rm_name_data), &rmpipe);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::not_found, res);

    {
        int count = 0;
        mtrie.match (add_name_data, getlen (add_name_data), mtrie_count,
                     &count);
        TEST_ASSERT_EQUAL_INT (1, count);
    }

    if (strncmp (add_name, rm_name,
                 std::min (strlen (add_name), strlen (rm_name) + 1))
        != 0) {
        int count = 0;
        mtrie.match (rm_name_data, getlen (rm_name_data), mtrie_count, &count);
        TEST_ASSERT_EQUAL_INT (0, count);
    }
}

void test_rm_nonexistent_nonempty_samename ()
{
    // TODO this triggers an assertion
    test_add_and_rm_other ("foo", "foo");
}

void test_rm_nonexistent_nonempty_differentname ()
{
    test_add_and_rm_other ("foo", "bar");
}

void test_rm_nonexistent_nonempty_prefix ()
{
    // TODO here, a test assertion fails
    test_add_and_rm_other ("foobar", "foo");
}

void test_rm_nonexistent_nonempty_prefixed ()
{
    test_add_and_rm_other ("foo", "foobar");
}

void add_indexed_expect_unique (zmq::generic_mtrie_t<int> &mtrie,
                                int *pipes,
                                const char **names,
                                size_t i)
{
    const zmq::generic_mtrie_t<int>::prefix_t name_data =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (names[i]);

    bool res = mtrie.add (name_data, getlen (name_data), &pipes[i]);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::last_value_removed, res);
}

void test_rm_nonexistent_between ()
{
    int pipes[3];
    const char *names[] = {"foo1", "foo2", "foo3"};

    zmq::generic_mtrie_t<int> mtrie;
    add_indexed_expect_unique (mtrie, pipes, names, 0);
    add_indexed_expect_unique (mtrie, pipes, names, 2);

    const zmq::generic_mtrie_t<int>::prefix_t name_data =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (names[1]);

    zmq::generic_mtrie_t<int>::rm_result res =
      mtrie.rm (name_data, getlen (name_data), &pipes[1]);
    TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::not_found, res);
}

template <size_t N>
void add_entries (zmq::generic_mtrie_t<int> &mtrie,
                  int (&pipes)[N],
                  const char *(&names)[N])
{
    for (size_t i = 0; i < N; ++i) {
        add_indexed_expect_unique (mtrie, pipes, names, i);
    }
}

void test_add_multiple ()
{
    int pipes[3];
    const char *names[] = {"foo1", "foo2", "foo3"};

    zmq::generic_mtrie_t<int> mtrie;
    add_entries (mtrie, pipes, names);

    for (size_t i = 0; i < sizeof (names) / sizeof (names[0]); ++i) {
        const zmq::generic_mtrie_t<int>::prefix_t name_data =
          reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (names[i]);
        int count = 0;
        mtrie.match (name_data, getlen (name_data), mtrie_count, &count);
        TEST_ASSERT_EQUAL_INT (1, count);
    }
}

void test_add_multiple_reverse ()
{
    int pipes[3];
    const char *names[] = {"foo1", "foo2", "foo3"};

    zmq::generic_mtrie_t<int> mtrie;
    for (int i = 2; i >= 0; --i) {
        add_indexed_expect_unique (mtrie, pipes, names, (size_t) i);
    }

    for (size_t i = 0; i < 3; ++i) {
        const zmq::generic_mtrie_t<int>::prefix_t name_data =
          reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (names[i]);
        int count = 0;
        mtrie.match (name_data, getlen (name_data), mtrie_count, &count);
        TEST_ASSERT_EQUAL_INT (1, count);
    }
}

template <size_t N> void add_and_rm_entries (const char *(&names)[N])
{
    int pipes[N];
    zmq::generic_mtrie_t<int> mtrie;
    add_entries (mtrie, pipes, names);

    for (size_t i = 0; i < N; ++i) {
        const zmq::generic_mtrie_t<int>::prefix_t name_data =
          reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (names[i]);

        zmq::generic_mtrie_t<int>::rm_result res =
          mtrie.rm (name_data, getlen (name_data), &pipes[i]);
        TEST_ASSERT_EQUAL (zmq::generic_mtrie_t<int>::last_value_removed, res);
    }
}

void test_rm_multiple_in_order ()
{
    const char *names[] = {"foo1", "foo2", "foo3"};
    add_and_rm_entries (names);
}

void test_rm_multiple_reverse_order ()
{
    const char *names[] = {"foo3", "foo2", "foo1"};
    add_and_rm_entries (names);
}

void check_name (zmq::generic_mtrie_t<int>::prefix_t data_,
                 size_t len_,
                 const char *name_)
{
    TEST_ASSERT_EQUAL_UINT (strlen (name_), len_);
    TEST_ASSERT_EQUAL_STRING_LEN (name_, data_, len_);
}

template <size_t N> void add_entries_rm_pipes_unique (const char *(&names)[N])
{
    int pipes[N];
    zmq::generic_mtrie_t<int> mtrie;
    add_entries (mtrie, pipes, names);

    for (size_t i = 0; i < N; ++i) {
        mtrie.rm (&pipes[i], check_name, names[i], false);
    }
}

void test_rm_with_callback_multiple_in_order ()
{
    const char *names[] = {"foo1", "foo2", "foo3"};

    add_entries_rm_pipes_unique (names);
}

void test_rm_with_callback_multiple_reverse_order ()
{
    const char *names[] = {"foo3", "foo2", "foo1"};

    add_entries_rm_pipes_unique (names);
}

void check_count (zmq::generic_mtrie_t<int>::prefix_t data_,
                  size_t len_,
                  int *count_)
{
    --(*count_);
    TEST_ASSERT_GREATER_OR_EQUAL (0, *count_);
}

void add_duplicate_entry (zmq::generic_mtrie_t<int> &mtrie, int (&pipes)[2])
{
    const char *name = "foo";

    const zmq::generic_mtrie_t<int>::prefix_t name_data =
      reinterpret_cast<zmq::generic_mtrie_t<int>::prefix_t> (name);

    bool res = mtrie.add (name_data, getlen (name_data), &pipes[0]);
    TEST_ASSERT_TRUE (res);
    res = mtrie.add (name_data, getlen (name_data), &pipes[1]);
    TEST_ASSERT_FALSE (res);
}

void test_rm_with_callback_duplicate ()
{
    int pipes[2];
    zmq::generic_mtrie_t<int> mtrie;
    add_duplicate_entry (mtrie, pipes);

    int count = 1;
    mtrie.rm (&pipes[0], check_count, &count, false);
    count = 1;
    mtrie.rm (&pipes[1], check_count, &count, false);
}

void test_rm_with_callback_duplicate_uniq_only ()
{
    int pipes[2];
    zmq::generic_mtrie_t<int> mtrie;
    add_duplicate_entry (mtrie, pipes);

    int count = 0;
    mtrie.rm (&pipes[0], check_count, &count, true);
    count = 1;
    mtrie.rm (&pipes[1], check_count, &count, true);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_create);
    RUN_TEST (test_check_empty_match_nonempty_data);
    RUN_TEST (test_check_empty_match_empty_data);
    RUN_TEST (test_add_single_entry_match_exact);
    RUN_TEST (test_add_single_entry_twice_match_exact);
    RUN_TEST (test_add_rm_single_entry_match_exact);
    RUN_TEST (test_add_two_entries_match_prefix_and_exact);
    RUN_TEST (test_add_two_entries_with_same_name_match_exact);

    RUN_TEST (test_rm_nonexistent_0_size_empty);
    RUN_TEST (test_rm_nonexistent_empty);
    RUN_TEST (test_rm_nonexistent_nonempty_samename);
    RUN_TEST (test_rm_nonexistent_nonempty_differentname);
    RUN_TEST (test_rm_nonexistent_nonempty_prefix);
    RUN_TEST (test_rm_nonexistent_nonempty_prefixed);
    RUN_TEST (test_rm_nonexistent_between);

    RUN_TEST (test_add_multiple);
    RUN_TEST (test_add_multiple_reverse);
    RUN_TEST (test_rm_multiple_in_order);
    RUN_TEST (test_rm_multiple_reverse_order);

    RUN_TEST (test_rm_with_callback_multiple_in_order);
    RUN_TEST (test_rm_with_callback_multiple_reverse_order);
    RUN_TEST (test_rm_with_callback_duplicate);
    RUN_TEST (test_rm_with_callback_duplicate_uniq_only);

    return UNITY_END ();
}
