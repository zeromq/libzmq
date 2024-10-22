/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_RANDOM_HPP_INCLUDED__
#define __ZMQ_RANDOM_HPP_INCLUDED__

#include "stdint.hpp"

namespace zmq
{
//  Seeds the random number generator.
void seed_random ();

//  Generates random value.
uint32_t generate_random ();

//  [De-]Initialise crypto library, if needed.
//  Serialised and refcounted, so that it can be called
//  from multiple threads, each with its own context, and from
//  the various zmq_utils curve functions safely.
void random_open ();
void random_close ();
}

#endif
