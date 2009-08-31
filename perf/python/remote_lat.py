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
import time


def main ():
    if len(sys.argv) != 5:
        print ('usage: py_remote_lat <in-interface> ' +
            '<out-interface> <message-size> <roundtrip-count>')
        sys.exit (1)

    try:
        message_size = int (sys.argv [3])
        roundtrip_count = int (sys.argv [4])
    except (ValueError, OverflowError), e:
        print 'message-size and message-count must be integers'
        sys.exit (1)

    z = libpyzmq.Zmq ()

    context = z.context (1,1)
 
    in_socket = z.socket (context, libpyzmq.ZMQ_SUB)
    out_socket = z.socket (context, libpyzmq.ZMQ_PUB)
    
    z.connect (in_socket, addr = in_interface)
    z.connect (out_socket, addr = out_interface)
        
    for i in range (0, roundtrip_count):
        list = z.receive (in_socket, True)
        message = list [1]
        z.send (out_socket, message, True)
 
    time.sleep (2)


if __name__ == "__main__":
    main ()
    
