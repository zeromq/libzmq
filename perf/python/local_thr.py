#
#    Copyright (c) 2007-2009 FastMQ Inc.
#
#    This file is part of 0MQ.
#
#    0MQ is free software; you can redistribute it and/or modify it under
#    the terms of the Lesser GNU General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    0MQ is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    Lesser GNU General Public License for more details.
#
#    You should have received a copy of the Lesser GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
from datetime import datetime
import libpyzmq

def main ():
    if len (sys.argv) != 4:
        print ('usage: py_local_thr <in_interface> <message-size> ' +
            '<message-count>')
        sys.exit (1)

    try:
        message_size = int (sys.argv [2])
        message_count = int (sys.argv [3])
    except (ValueError, OverflowError), e:
        print 'message-size and message-count must be integers'
        sys.exit (1)

    print "message size:", message_size, "[B]"
    print "message count:", message_count

    z = libpyzmq.Zmq ()

    context = z.context (1,1)
    in_socket = z.socket (context, libpyzmq.ZMQ_SUB)
    z.connect (in_socketaddr = sys.argv [1])
    

    list = z.receive (in_socket, True)
    msg = list [1]
    assert len(msg) == message_size
    start = datetime.now ()
    for i in range (1, message_count):
        list = z.receive (in_socket, True)
        msg = list [1]
        assert len(msg) == message_size
    end = datetime.now()

    delta = end - start
    delta_us = delta.seconds * 1000000 + delta.microseconds
    if delta_us == 0:
    	delta_us = 1
    message_thr = (1000000.0 * float (message_count)) / float (delta_us)
    megabit_thr = (message_thr * float (message_size) * 8.0) / 1000000.0;

    print "Your average throughput is %.0f [msg/s]" % (message_thr, )
    print "Your average throughput is %.2f [Mb/s]" % (megabit_thr, )

if __name__ == "__main__":
    main ()
