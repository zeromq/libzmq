/* SPDX-License-Identifier: MPL-2.0 */

#if __cplusplus >= 201103L

#include "generic_mtrie_impl.hpp"

#include <chrono>
#include <cstdio>
#include <random>
#include <ratio>
#include <vector>
#include <string>

const std::size_t nprefix = 1000000;
const std::size_t samples = 10;

template <class T>
void benchmark_add (
  T &subscriptions_,
  std::vector<std::pair<zmq::generic_mtrie_t<uint64_t>::prefix_t, size_t> >
    &prefixes_,
  uint64_t *pipes_)
{
    using namespace std::chrono;
    std::vector<duration<long, std::nano> > samples_vec;
    samples_vec.reserve (samples);

    for (std::size_t run = 0; run < samples; ++run) {
        duration<long, std::nano> interval (0);
        for (std::size_t i = 0; i < prefixes_.size (); i++) {
            auto start = steady_clock::now ();
            subscriptions_.add (prefixes_[i].first, prefixes_[i].second,
                                &pipes_[i]);
            auto end = steady_clock::now ();
            interval += end - start;
        }
        samples_vec.push_back (interval / prefixes_.size ());
    }

    std::size_t sum = 0;
    for (const auto &sample : samples_vec)
        sum += sample.count ();
    std::printf ("Average operation time = %.1lf ns\n",
                 static_cast<double> (sum) / samples);
}

template <class T>
void benchmark_rm (
  T &subscriptions_,
  std::vector<std::pair<zmq::generic_mtrie_t<uint64_t>::prefix_t, size_t> >
    &prefixes_,
  uint64_t *pipes_)
{
    using namespace std::chrono;
    std::vector<duration<long, std::nano> > samples_vec;
    samples_vec.reserve (samples);

    for (std::size_t run = 0; run < samples; ++run) {
        duration<long, std::nano> interval (0);
        for (std::size_t i = 0; i < prefixes_.size (); i++) {
            auto start = steady_clock::now ();
            subscriptions_.rm (prefixes_[i].first, prefixes_[i].second,
                               &pipes_[i]);
            auto end = steady_clock::now ();
            interval += end - start;
        }
        samples_vec.push_back (interval / prefixes_.size ());
    }

    std::size_t sum = 0;
    for (const auto &sample : samples_vec)
        sum += sample.count ();
    std::printf ("Average operation time = %.1lf ns\n",
                 static_cast<double> (sum) / samples);
}

int main ()
{
    // Generate input set.
    uint64_t pipes[nprefix];
    std::vector<std::pair<zmq::generic_mtrie_t<uint64_t>::prefix_t, size_t> >
      prefixes;
    prefixes.reserve (nprefix);
    for (std::size_t i = 0; i < nprefix; ++i) {
        char prefix[100];
        size_t len = sprintf (prefix, "prefix_%lu", i);
        prefixes.push_back (std::make_pair (
          reinterpret_cast<zmq::generic_mtrie_t<uint64_t>::prefix_t> (prefix),
          len));
    }

    // Initialize data structures.
    //
    // Keeping initialization out of the benchmarking function helps
    // heaptrack detect peak memory consumption of the radix tree.
    zmq::generic_mtrie_t<uint64_t> mtrie;

    // Create a benchmark.
    std::printf ("prefixes = %llu\n",
                 static_cast<unsigned long long> (nprefix));
    std::puts ("[generic_mtrie::add]");
    benchmark_add (mtrie, prefixes, pipes);

    std::puts ("[generic_mtrie::rm]");
    benchmark_rm (mtrie, prefixes, pipes);
}

#else

int main ()
{
}

#endif
