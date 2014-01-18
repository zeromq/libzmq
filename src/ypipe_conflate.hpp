/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

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

    template <typename T> class ypipe_conflate_t : public ypipe_base_t <T>
    {
    public:

        //  Initialises the pipe.
        inline ypipe_conflate_t ()
            : reader_awake(false)
        {
        }

        //  The destructor doesn't have to be virtual. It is mad virtual
        //  just to keep ICC and code checking tools from complaining.
        inline virtual ~ypipe_conflate_t ()
        {
        }

        //  Following function (write) deliberately copies uninitialised data
        //  when used with zmq_msg. Initialising the VSM body for
        //  non-VSM messages won't be good for performance.

#ifdef ZMQ_HAVE_OPENVMS
#pragma message save
#pragma message disable(UNINIT)
#endif
        inline void write (const T &value_, bool incomplete_)
        {
            (void)incomplete_;

            dbuffer.write (value_);
        }

#ifdef ZMQ_HAVE_OPENVMS
#pragma message restore
#endif

        // There are no incomplete items for conflate ypipe
        inline bool unwrite (T *)
        {
            return false;
        }

        //  Flush is no-op for conflate ypipe. Reader asleep behaviour
        //  is as of the usual ypipe.
        //  Returns false if the reader thread is sleeping. In that case,
        //  caller is obliged to wake the reader up before using the pipe again.
        inline bool flush ()
        {
            return reader_awake;
        }

        //  Check whether item is available for reading.
        inline bool check_read ()
        {
            bool res = dbuffer.check_read ();
            if (!res)
                reader_awake = false;

            return res;
        }

        //  Reads an item from the pipe. Returns false if there is no value.
        //  available.
        inline bool read (T *value_)
        {
            if (!check_read ())
                return false;

            return dbuffer.read (value_);
        }

        //  Applies the function fn to the first elemenent in the pipe
        //  and returns the value returned by the fn.
        //  The pipe mustn't be empty or the function crashes.
        inline bool probe (bool (*fn)(const T &))
        {
            return dbuffer.probe (fn);
        }

    protected:

        dbuffer_t <T> dbuffer;
        bool reader_awake;

        //  Disable copying of ypipe object.
        ypipe_conflate_t (const ypipe_conflate_t&);
        const ypipe_conflate_t &operator = (const ypipe_conflate_t&);
    };

}

#endif
