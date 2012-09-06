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

#ifndef __ZMQ_RANDOM_HPP_INCLUDED__
#define __ZMQ_RANDOM_HPP_INCLUDED__

#include "stdint.hpp"
#include "mutex.hpp"

namespace zmq
{
	class mersenne_twister_t
	{
		static const uint32_t _MT32_N = 624;
		static const uint32_t _MT32_M = 397;
		static const uint32_t _MT32_MATRIX_A = 0x9908b0dfUL;   /* constant vector a */
		static const uint32_t _MT32_UPPER_MASK = 0x80000000UL; /* most significant w-r bits */
		static const uint32_t _MT32_LOWER_MASK = 0x7fffffffUL; /* least significant r bits */

		uint32_t mt[_MT32_N];
		uintptr_t mti;
		mutex_t state_sync;

	public:
		mersenne_twister_t () { seed (); }
		void seed (uint32_t seed = 0x0);
		uint32_t generate ();
	};

	extern mersenne_twister_t random;
}

#endif
