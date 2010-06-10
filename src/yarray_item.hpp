/*
    Copyright (c) 2007-2010 iMatix Corporation

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

#ifndef __ZMQ_YARRAY_ITEM_INCLUDED__
#define __ZMQ_YARRAY_ITEM_INCLUDED__

namespace zmq
{

    //  Base class for objects stored in yarray. Note that each object can
    //  be stored in at most one yarray.

    class yarray_item_t
    {
    public:

        inline yarray_item_t () :
            yarray_index (-1)
        {
        }

        //  The destructor doesn't have to be virtual. It is mad virtual
        //  just to keep ICC and code checking tools from complaining.
        inline virtual ~yarray_item_t ()
        {
        }

        inline void set_yarray_index (int index_)
        {
            yarray_index = index_;
        }

        inline int get_yarray_index ()
        {
            return yarray_index;
        }

    private:

        int yarray_index;

        yarray_item_t (const yarray_item_t&);
        void operator = (const yarray_item_t&);
    };

}

#endif
