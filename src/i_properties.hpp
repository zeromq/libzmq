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

#ifndef __ZMQ_I_PROPERTIES_HPP_INCLUDED__
#define __ZMQ_I_PROPERTIES_HPP_INCLUDED__

namespace zmq
{
    //  Interface for accessing message properties.
    //  Implementers are supposed to use reference counting to
    //  manage object's lifetime.

    struct i_properties
    {
        virtual ~i_properties () {}

        //  Returns pointer to property value or NULL if
        //  property not found.
        virtual const char *get (const char *property) const = 0;

        virtual void add_ref () = 0;

        //  Drop reference. Returns true iff the reference
        //  counter drops to zero.
        virtual bool drop_ref () = 0;
    };
}

#endif
