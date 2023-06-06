/* SPDX-License-Identifier: MPL-2.0 */

#if __cplusplus >= 201103L

#include "radix_tree.hpp"
#include "trie.hpp"

#include <chrono>
#include <cstddef>
#include <cstdio>
#include <random>
#include <ratio>
#include <vector>

const std::size_t nkeys = 10000;
const std::size_t nqueries = 1000000;
const std::size_t warmup_runs = 10;
const std::size_t samples = 10;
const std::size_t key_length = 20;
const char *chars = "abcdefghijklmnopqrstuvwxyz0123456789";
const int chars_len = 36;

template <class T>
void benchmark_lookup (T &subscriptions_,
                       std::vector<unsigned char *> &queries_)
{
    using namespace std::chrono;
    std::vector<duration<long, std::nano> > samples_vec;
    samples_vec.reserve (samples);

    for (std::size_t run = 0; run < warmup_runs; ++run) {
        for (auto &query : queries_)
            subscriptions_.check (query, key_length);
    }

    for (std::size_t run = 0; run < samples; ++run) {
        duration<long, std::nano> interval (0);
        for (auto &query : queries_) {
            auto start = steady_clock::now ();
            subscriptions_.check (query, key_length);
            auto end = steady_clock::now ();
            interval += end - start;
        }
        samples_vec.push_back (interval / queries_.size ());
    }

    std::size_t sum = 0;
    for (const auto &sample : samples_vec)
        sum += sample.count ();
    std::printf ("Average lookup time = %.1lf ns\n",
                 static_cast<double> (sum) / samples);
}

int main ()
{
    // Generate input set.
    std::minstd_rand rng (123456789);
    std::vector<unsigned char *> input_set;
    std::vector<unsigned char *> queries;
    input_set.reserve (nkeys);
    queries.reserve (nqueries);

    for (std::size_t i = 0; i < nkeys; ++i) {
        unsigned char *key = new unsigned char[key_length];
        for (std::size_t j = 0; j < key_length; j++)
            key[j] = static_cast<unsigned char> (chars[rng () % chars_len]);
        input_set.emplace_back (key);
    }
    for (std::size_t i = 0; i < nqueries; ++i)
        queries.push_back (input_set[rng () % nkeys]);

    // Initialize both data structures.
    //
    // Keeping initialization out of the benchmarking function helps
    // heaptrack detect peak memory consumption of the radix tree.
    zmq::trie_t trie;
    zmq::radix_tree_t radix_tree;
    for (auto &key : input_set) {
        trie.add (key, key_length);
        radix_tree.add (key, key_length);
    }

    // Create a benchmark.
    std::printf ("keys = %llu, queries = %llu, key size = %llu\n",
                 static_cast<unsigned long long> (nkeys),
                 static_cast<unsigned long long> (nqueries),
                 static_cast<unsigned long long> (key_length));
    std::puts ("[trie]");
    benchmark_lookup (trie, queries);

    std::puts ("[radix_tree]");
    benchmark_lookup (radix_tree, queries);

    for (auto &op : input_set)
        delete[] op;
}

#else

int main ()
{
}

#endif
