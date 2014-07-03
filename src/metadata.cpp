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

#include "metadata.hpp"

zmq::metadata_t::metadata_t (const dict_t &dict) :
    ref_cnt (1),
    dict (dict)
{
}

zmq::metadata_t::~metadata_t ()
{
}

const char *zmq::metadata_t::get (const std::string &property) const
{
    dict_t::const_iterator it = dict.find (property);
    if (it == dict.end ())
        return NULL;
    else
        return it->second.c_str ();
}

void zmq::metadata_t::add_ref ()
{
    ref_cnt.add (1);
}

bool zmq::metadata_t::drop_ref ()
{
    return !ref_cnt.sub (1);
}
