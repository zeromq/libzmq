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

#ifndef __ZS_YQUEUE_HPP_INCLUDED__
#define __ZS_YQUEUE_HPP_INCLUDED__

#include <stddef.h>

#include "err.hpp"

namespace zs
{

    //  yqueue is an efficient queue implementation. The main goal is
    //  to minimise number of allocations/deallocations needed. Thus yqueue
    //  allocates/deallocates elements in batches of N.
    //
    //  yqueue allows one thread to use push/back function and another one 
    //  to use pop/front functions. However, user must ensure that there's no
    //  pop on the empty queue and that both threads don't access the same
    //  element in unsynchronised manner.
    //
    //  T is the type of the object in the queue
    //  N is granularity of the queue (how many pushes have to be done till
    //  actual memory allocation is required)

    template <typename T, int N> class yqueue_t
    {
    public:

        //  Create the queue.
        inline yqueue_t ()
        {
             begin_chunk = new chunk_t;
             zs_assert (begin_chunk);
             begin_pos = 0;
             back_chunk = NULL;
             back_pos = 0;
             end_chunk = begin_chunk;
             end_pos = 0;
        }

        //  Destroy the queue.
        inline ~yqueue_t ()
        {
            while (true) {
                chunk_t *o = begin_chunk;
                begin_chunk = begin_chunk->next;
                delete o;
                if (o == end_chunk)
                    break;
            }
        }

        //  Returns reference to the front element of the queue.
        //  If the queue is empty, behaviour is undefined.
        inline T &front ()
        {
             return begin_chunk->values [begin_pos];
        }

        //  Returns reference to the back element of the queue.
        //  If the queue is empty, behaviour is undefined.
        inline T &back ()
        {
            return back_chunk->values [back_pos];
        }

        //  Adds an element to the back end of the queue.
        inline void push ()
        {
            back_chunk = end_chunk;
            back_pos = end_pos;

            if (++ end_pos != N)
                return;

            end_chunk->next = new chunk_t;
            zs_assert (end_chunk->next);
            end_chunk = end_chunk->next;
            end_pos = 0;
        }

        //  Removes an element from the front end of the queue.
        inline void pop ()
        {
            if (++ begin_pos == N) {
                chunk_t *o = begin_chunk;
                begin_chunk = begin_chunk->next;
                begin_pos = 0;
                delete o;
            }
        }

    private:

        //  Individual memory chunk to hold N elements.
        struct chunk_t
        {
             T values [N];
             chunk_t *next;
        };

        //  Back position may point to invalid memory if the queue is empty,
        //  while begin & end positions are always valid. Begin position is
        //  accessed exclusively be queue reader (front/pop), while back and
        //  end positions are accessed exclusively by queue writer (back/push).
        chunk_t *begin_chunk;
        int begin_pos;
        chunk_t *back_chunk;
        int back_pos;
        chunk_t *end_chunk;
        int end_pos;

        //  Disable copying of yqueue.
        yqueue_t (const yqueue_t&);
        void operator = (const yqueue_t&);
    };

}

#endif
