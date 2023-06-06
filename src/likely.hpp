/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_LIKELY_HPP_INCLUDED__
#define __ZMQ_LIKELY_HPP_INCLUDED__

#if defined __GNUC__
#define likely(x) __builtin_expect ((x), 1)
#define unlikely(x) __builtin_expect ((x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif


#endif
