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

#include <radix_tree.hpp>
#include <stdint.hpp>

#include <set>
#include <string>
#include <string.h>
#include <unity.h>
#include <vector>

void setUp ()
{
}
void tearDown ()
{
}

bool tree_add (zmq::radix_tree_t &tree_, const std::string &key_)
{
    return tree_.add (reinterpret_cast<const unsigned char *> (key_.data ()),
                      key_.size ());
}

bool tree_rm (zmq::radix_tree_t &tree_, const std::string &key_)
{
    return tree_.rm (reinterpret_cast<const unsigned char *> (key_.data ()),
                     key_.size ());
}

bool tree_check (zmq::radix_tree_t &tree_, const std::string &key_)
{
    return tree_.check (reinterpret_cast<const unsigned char *> (key_.data ()),
                        key_.size ());
}

void test_empty ()
{
    zmq::radix_tree_t tree;

    TEST_ASSERT_TRUE (tree.size () == 0);
}

void test_add_single_entry ()
{
    zmq::radix_tree_t tree;

    TEST_ASSERT_TRUE (tree_add (tree, "foo"));
}

void test_add_same_entry_twice ()
{
    zmq::radix_tree_t tree;

    TEST_ASSERT_TRUE (tree_add (tree, "test"));
    TEST_ASSERT_FALSE (tree_add (tree, "test"));
}

void test_rm_when_empty ()
{
    zmq::radix_tree_t tree;

    TEST_ASSERT_FALSE (tree_rm (tree, "test"));
}

void test_rm_single_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "temporary");
    TEST_ASSERT_TRUE (tree_rm (tree, "temporary"));
}

void test_rm_unique_entry_twice ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "test");
    TEST_ASSERT_TRUE (tree_rm (tree, "test"));
    TEST_ASSERT_FALSE (tree_rm (tree, "test"));
}

void test_rm_duplicate_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "test");
    tree_add (tree, "test");
    TEST_ASSERT_FALSE (tree_rm (tree, "test"));
    TEST_ASSERT_TRUE (tree_rm (tree, "test"));
}

void test_rm_common_prefix ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "checkpoint");
    tree_add (tree, "checklist");
    TEST_ASSERT_FALSE (tree_rm (tree, "check"));
}

void test_rm_common_prefix_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "checkpoint");
    tree_add (tree, "checklist");
    tree_add (tree, "check");
    TEST_ASSERT_TRUE (tree_rm (tree, "check"));
}

void test_rm_null_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "");
    TEST_ASSERT_TRUE (tree_rm (tree, ""));
}

void test_check_empty ()
{
    zmq::radix_tree_t tree;

    TEST_ASSERT_FALSE (tree_check (tree, "foo"));
}

void test_check_added_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "entry");
    TEST_ASSERT_TRUE (tree_check (tree, "entry"));
}

void test_check_common_prefix ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "introduce");
    tree_add (tree, "introspect");
    TEST_ASSERT_FALSE (tree_check (tree, "intro"));
}

void test_check_prefix ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "toasted");
    TEST_ASSERT_FALSE (tree_check (tree, "toast"));
    TEST_ASSERT_FALSE (tree_check (tree, "toaste"));
    TEST_ASSERT_FALSE (tree_check (tree, "toaster"));
}

void test_check_nonexistent_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "red");
    TEST_ASSERT_FALSE (tree_check (tree, "blue"));
}

void test_check_query_longer_than_entry ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "foo");
    TEST_ASSERT_TRUE (tree_check (tree, "foobar"));
}

void test_check_null_entry_added ()
{
    zmq::radix_tree_t tree;

    tree_add (tree, "");
    TEST_ASSERT_TRUE (tree_check (tree, "all queries return true"));
}

void test_size ()
{
    zmq::radix_tree_t tree;

    // Adapted from the example on wikipedia.
    std::vector<std::string> keys;
    keys.push_back ("tester");
    keys.push_back ("water");
    keys.push_back ("slow");
    keys.push_back ("slower");
    keys.push_back ("test");
    keys.push_back ("team");
    keys.push_back ("toast");

    for (size_t i = 0; i < keys.size (); ++i)
        TEST_ASSERT_TRUE (tree_add (tree, keys[i]));
    TEST_ASSERT_TRUE (tree.size () == keys.size ());
    for (size_t i = 0; i < keys.size (); ++i)
        TEST_ASSERT_FALSE (tree_add (tree, keys[i]));
    TEST_ASSERT_TRUE (tree.size () == 2 * keys.size ());
    for (size_t i = 0; i < keys.size (); ++i)
        TEST_ASSERT_FALSE (tree_rm (tree, keys[i]));
    TEST_ASSERT_TRUE (tree.size () == keys.size ());
    for (size_t i = 0; i < keys.size (); ++i)
        TEST_ASSERT_TRUE (tree_rm (tree, keys[i]));
    TEST_ASSERT_TRUE (tree.size () == 0);
}

void return_key (unsigned char *data, size_t size, void *arg)
{
    std::vector<std::string> *vec =
      reinterpret_cast<std::vector<std::string> *> (arg);
    std::string key;
    for (size_t i = 0; i < size; ++i)
        key.push_back (static_cast<char> (data[i]));
    vec->push_back (key);
}

void test_apply ()
{
    zmq::radix_tree_t tree;

    std::set<std::string> keys;
    keys.insert ("tester");
    keys.insert ("water");
    keys.insert ("slow");
    keys.insert ("slower");
    keys.insert ("test");
    keys.insert ("team");
    keys.insert ("toast");

    const std::set<std::string>::iterator end = keys.end ();
    for (std::set<std::string>::iterator it = keys.begin (); it != end; ++it)
        tree_add (tree, *it);

    std::vector<std::string> *vec = new std::vector<std::string> ();
    tree.apply (return_key, static_cast<void *> (vec));
    for (size_t i = 0; i < vec->size (); ++i)
        TEST_ASSERT_TRUE (keys.count ((*vec)[i]) > 0);
    delete vec;
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_empty);
    RUN_TEST (test_add_single_entry);
    RUN_TEST (test_add_same_entry_twice);

    RUN_TEST (test_rm_when_empty);
    RUN_TEST (test_rm_single_entry);
    RUN_TEST (test_rm_unique_entry_twice);
    RUN_TEST (test_rm_duplicate_entry);
    RUN_TEST (test_rm_common_prefix);
    RUN_TEST (test_rm_common_prefix_entry);
    RUN_TEST (test_rm_null_entry);

    RUN_TEST (test_check_empty);
    RUN_TEST (test_check_added_entry);
    RUN_TEST (test_check_common_prefix);
    RUN_TEST (test_check_prefix);
    RUN_TEST (test_check_nonexistent_entry);
    RUN_TEST (test_check_query_longer_than_entry);
    RUN_TEST (test_check_null_entry_added);

    RUN_TEST (test_size);

    RUN_TEST (test_apply);

    return UNITY_END ();
}
