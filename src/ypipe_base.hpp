
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

#ifndef __ZMQ_YPIPE_BASE_HPP_INCLUDED__
#define __ZMQ_YPIPE_BASE_HPP_INCLUDED__


namespace zmq
{
    // ypipe_base abstracts ypipe and ypipe_conflate specific
    // classes, one is selected according to a the conflate
    // socket option

    template <typename T> class ypipe_base_t
    {
    public:
        virtual ~ypipe_base_t () {}
        virtual void write (const T &value_, bool incomplete_) = 0;
        virtual bool unwrite (T *value_) = 0;
        virtual bool flush () = 0;
        virtual bool check_read () = 0;
        virtual bool read (T *value_) = 0;
        virtual bool probe (bool (*fn)(const T &)) = 0;
    };
}

#endif
