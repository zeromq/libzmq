/*
    Copyright (c) 2007-2009 FastMQ Inc.

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_YPIPE_HPP_INCLUDED__
#define __ZMQ_YPIPE_HPP_INCLUDED__

#include "atomic_ptr.hpp"
#include "yqueue.hpp"
#include "platform.hpp"

namespace zmq
{

    //  Lock-free queue implementation.
    //  Only a single thread can read from the pipe at any specific moment.
    //  Only a single thread can write to the pipe at any specific moment.
    //
    //  T is the type of the object in the queue.
    //  If the template parameter D is set to true, it is quaranteed that
    //  the pipe will die in a finite time (so that you can swich to some
    //  other task). If D is set to false, reading from the pipe may result
    //  in an infinite cycle (if the pipe is continuosly fed by new elements).
    //  N is granularity of the pipe (how many elements have to be inserted
    //  till actual memory allocation is required).

    template <typename T, bool D, int N> class ypipe_t
    {
    public:

        //  Initialises the pipe. In D scenario it is created in dead state.
        //  Otherwise it's alive.
        inline ypipe_t () :
            stop (false)
        {
            //  Insert terminator element into the queue.
            queue.push ();

            //  Let all the pointers to point to the terminator
            //  (unless pipe is dead, in which case c is set to NULL).
            r = w = &queue.back ();
            c.set (D ? NULL : &queue.back ());
        }

        //  Following function (write) deliberately copies uninitialised data
        //  when used with zmq_msg. Initialising the VSM body for
        //  non-VSM messages won't be good for performance.

#ifdef ZMQ_HAVE_OPENVMS
#pragma message save
#pragma message disable(UNINIT)
#endif

        //  Write an item to the pipe.  Don't flush it yet.
        inline void write (const T &value_)
        {
            //  Place the value to the queue, add new terminator element.
            queue.back () = value_;
            queue.push ();
        }

#ifdef ZMQ_HAVE_OPENVMS
#pragma message restore
#endif

        //  Flush the messages into the pipe. Returns false if the reader
        //  thread is sleeping. In that case, caller is obliged to wake the
        //  reader up before using the pipe again.
        inline bool flush ()
        {
            //  If there are no un-flushed items, do nothing.
            if (w == &queue.back ())
                return true;

            //  Try to set 'c' to 'back'
            if (c.cas (w, &queue.back ()) != w) {

                //  Compare-and-swap was unseccessful because 'c' is NULL.
                //  This means that the reader is asleep. Therefore we don't
                //  care about thread-safeness and update c in non-atomic
                //  manner. We'll return false to let the caller know
                //  that reader is sleeping.
                c.set (&queue.back ());
                w = &queue.back ();
                return false;
            }

            //  Reader is alive. Nothing special to do now. Just move
            //  the 'first un-flushed item' pointer to the end of the queue.
            w = &queue.back ();
            return true;
        }

        //  Check whether item is available for reading.
        inline bool check_read ()
        {
            //  Was the value prefetched already? If so, return.
            if (&queue.front () != r)
                 return true;

            //  There's no prefetched value, so let us prefetch more values.
            //  (Note that D is a template parameter. Becaue of that one of
            //  the following branches will be completely optimised away
            //  by the compiler.)
            if (D) {

                //  If one prefetch was already done since last sleeping,
                //  don't do a new one, rather ask caller to go asleep.
                if (stop) {
                    stop = false;
                    return false;
                }

                //  Get new items. Perform the operation in atomic fashion.
                r = c.xchg (NULL);

                //  If there are no elements prefetched, exit and go asleep.
                //  During pipe's lifetime r should never be NULL, however,
                //  during pipe shutdown when retrieving messages from it
                //  to deallocate them, this can happen.
                if (&queue.front () == r || !r) {
                    stop = false;
                    return false;
                }
                else {

                    //  We want to do only a single prefetch in D scenario
                    //  before going asleep. Thus, we set stop variable to true
                    //  so that we can return false next time the prefetch is
                    //  attempted.
                    stop = true;
                }
            }
            else {

                //  Prefetching in non-D scenario is to simply retrieve the
                //  pointer from c in atomic fashion. If there are no
                //  items to prefetch, set c to NULL (using compare-and-swap).
                r = c.cas (&queue.front (), NULL);

                //  If there are no elements prefetched, exit.
                //  During pipe's lifetime r should never be NULL, however,
                //  it can happen during pipe shutdown when messages
                //  are being deallocated.
                if (&queue.front () == r || !r)
                    return false;
            }

            //  There was at least one value prefetched.
            return true;
        }

        //  Reads an item from the pipe. Returns false if there is no value.
        //  available.
        inline bool read (T *value_)
        {
            //  Try to prefetch a value.
            if (!check_read ())
                return false;

            //  There was at least one value prefetched.
            //  Return it to the caller.
            *value_ = queue.front ();
            queue.pop ();
            return true;
        }

    protected:

        //  Allocation-efficient queue to store pipe items.
        //  Front of the queue points to the first prefetched item, back of
        //  the pipe points to last un-flushed item. Front is used only by
        //  reader thread, while back is used only by writer thread.
        yqueue_t <T, N> queue;

        //  Points to the first un-flushed item. This variable is used
        //  exclusively by writer thread.
        T *w;

        //  Points to the first un-prefetched item. This variable is used
        //  exclusively by reader thread.
        T *r;

        //  The single point of contention between writer and reader thread.
        //  Points past the last flushed item. If it is NULL,
        //  reader is asleep. This pointer should be always accessed using
        //  atomic operations.
        atomic_ptr_t <T> c;

        //  Used only if 'D' template parameter is set to true. If true,
        //  prefetch was already done since last sleeping and the reader
        //  should go asleep instead of prefetching once more.
        bool stop;

        //  Disable copying of ypipe object.
        ypipe_t (const ypipe_t&);
        void operator = (const ypipe_t&);
    };

}

#endif
