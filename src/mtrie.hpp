/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MTRIE_HPP_INCLUDED__
#define __ZMQ_MTRIE_HPP_INCLUDED__

#include "generic_mtrie.hpp"

#if __cplusplus >= 201103L || (defined(_MSC_VER) && _MSC_VER > 1600)
#define ZMQ_HAS_EXTERN_TEMPLATE 1
#else
#define ZMQ_HAS_EXTERN_TEMPLATE 0
#endif

namespace zmq
{
class pipe_t;

#if ZMQ_HAS_EXTERN_TEMPLATE
extern template class generic_mtrie_t<pipe_t>;
#endif

typedef generic_mtrie_t<pipe_t> mtrie_t;
}

#endif
