/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_YPIPE_CONFLATE_HPP_INCLUDED__
#define __ZMQ_YPIPE_CONFLATE_HPP_INCLUDED__

#include "platform.hpp"
#include "dbuffer.hpp"
#include "ypipe_base.hpp"

namespace zmq
{
//  Adapter for dbuffer, to plug it in instead of a queue for the sake
//  of implementing the conflate socket option, which, if set, makes
//  the receiving side to discard all incoming messages but the last one.
//
//  reader_awake flag is needed here to mimic ypipe delicate behaviour
//  around the reader being asleep (see 'c' pointer being NULL in ypipe.hpp)

template <typename T> class ypipe_conflate_t ZMQ_FINAL : public ypipe_base_t<T>
{
  public:
    //  Initialises the pipe.
    ypipe_conflate_t () : reader_awake (false) {}

    //  Following function (write) deliberately copies uninitialised data
    //  when used with zmq_msg. Initialising the VSM body for
    //  non-VSM messages won't be good for performance.

#ifdef ZMQ_HAVE_OPENVMS
#pragma message save
#pragma message disable(UNINIT)
#endif
    void write (const T &value_, bool incomplete_)
    {
        (void) incomplete_;

        dbuffer.write (value_);
    }

#ifdef ZMQ_HAVE_OPENVMS
#pragma message restore
#endif

    // There are no incomplete items for conflate ypipe
    bool unwrite (T *)
    {
        return false;
    }

    //  Flush is no-op for conflate ypipe. Reader asleep behaviour
    //  is as of the usual ypipe.
    //  Returns false if the reader thread is sleeping. In that case,
    //  caller is obliged to wake the reader up before using the pipe again.
    bool flush ()
    {
        return reader_awake;
    }

    //  Check whether item is available for reading.
    bool check_read ()
    {
        const bool res = dbuffer.check_read ();
        if (!res)
            reader_awake = false;

        return res;
    }

    //  Reads an item from the pipe. Returns false if there is no value.
    //  available.
    bool read (T *value_)
    {
        if (!check_read ())
            return false;

        return dbuffer.read (value_);
    }

    //  Applies the function fn to the first element in the pipe
    //  and returns the value returned by the fn.
    //  The pipe mustn't be empty or the function crashes.
    bool probe (bool (*fn_) (const T &))
    {
        return dbuffer.probe (fn_);
    }

  protected:
    dbuffer_t<T> dbuffer;
    bool reader_awake;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ypipe_conflate_t)
};
}

#endif
