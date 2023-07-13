/*
    Copyright (c) 2023 Contributors as noted in the AUTHORS file

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
