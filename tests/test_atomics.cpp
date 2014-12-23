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

#include "testutil.hpp"

int main (void)
{
    void *counter = zmq_atomic_counter_new ();
    assert (zmq_atomic_counter_value (counter) == 0);
    assert (zmq_atomic_counter_inc (counter) == 0);
    assert (zmq_atomic_counter_inc (counter) == 1);
    assert (zmq_atomic_counter_inc (counter) == 2);
    assert (zmq_atomic_counter_value (counter) == 3);
    assert (zmq_atomic_counter_dec (counter) == true);
    assert (zmq_atomic_counter_dec (counter) == true);
    assert (zmq_atomic_counter_dec (counter) == false);
    zmq_atomic_counter_set (counter, 2);
    assert (zmq_atomic_counter_dec (counter) == true);
    assert (zmq_atomic_counter_dec (counter) == false);
    zmq_atomic_counter_destroy (&counter);
    return 0;
}
