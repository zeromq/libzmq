
/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_YPIPE_BASE_HPP_INCLUDED__
#define __ZMQ_YPIPE_BASE_HPP_INCLUDED__

#include "macros.hpp"

namespace zmq
{
// ypipe_base abstracts ypipe and ypipe_conflate specific
// classes, one is selected according to a the conflate
// socket option

template <typename T> class ypipe_base_t
{
  public:
    virtual ~ypipe_base_t () ZMQ_DEFAULT;
    virtual void write (const T &value_, bool incomplete_) = 0;
    virtual bool unwrite (T *value_) = 0;
    virtual bool flush () = 0;
    virtual bool check_read () = 0;
    virtual bool read (T *value_) = 0;
    virtual bool probe (bool (*fn_) (const T &)) = 0;
};
}

#endif
