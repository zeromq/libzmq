/*
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2011 Other contributors as noted in the AUTHORS file

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

#include <stdlib.h>

#include "platform.hpp"
#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#endif

#include "random.hpp"
#include "stdint.hpp"
#include "clock.hpp"

void zmq::mersenne_twister_t::seed (uint32_t seed)
{
	if (seed == 0) {
#if defined ZMQ_HAVE_WINDOWS
		seed = (uint32_t) GetCurrentProcessId ();
#else
		seed = (uint32_t) getpid ();
#endif

		seed += clock_t::now_us ();
	}

	mt[0] = seed;
	for (mti = 1; mti < _MT32_N; ++mti)
		mt[mti] = (1812433253UL * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti);
}

/**
 * Thread-safe Mersenne Twister 
 *
 * Based on the original implementation, copyright (C) 1997 - 2002,
 * Makoto Matsumoto and Takuji Nishimura, All rights reserved.  
 *
 * Originally licensed under BSD
 *
 * See: http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
 */
uint32_t zmq::mersenne_twister_t::generate ()
{
	uint32_t y;

	state_sync.lock ();

	if (mti >= _MT32_N) {
		uintptr_t kk;

		for (kk = 0; kk < _MT32_N-_MT32_M; ++kk) {
			uint32_t x = (mt[kk] & _MT32_UPPER_MASK) | (mt[kk+1] & _MT32_LOWER_MASK);
			mt[kk] = mt[kk + _MT32_M] ^ (x >> 1) ^ ((x & 1) * _MT32_MATRIX_A);
		}

		for (; kk<_MT32_N-1; ++kk) {
			uint32_t x = (mt[kk] & _MT32_UPPER_MASK) | (mt[kk+1] & _MT32_LOWER_MASK);
			mt[kk] = mt[kk + (_MT32_M - _MT32_N)] ^ (x >> 1) ^ ((x & 1) * _MT32_MATRIX_A);
		}

		uint32_t x = (mt[_MT32_N - 1] & _MT32_UPPER_MASK) | (mt[0] & _MT32_LOWER_MASK);

		mt[_MT32_N - 1] = mt[_MT32_M - 1] ^ (x >> 1) ^ ((x & 1) * _MT32_MATRIX_A);
		mti = 0;
	}

	y = mt[mti++];
	state_sync.unlock ();

	y ^= (y >> 11);
	y ^= (y << 7) & 0x9d2c5680UL;
	y ^= (y << 15) & 0xefc60000UL;
	y ^= (y >> 18);

	return y;
}

zmq::mersenne_twister_t zmq::random;

