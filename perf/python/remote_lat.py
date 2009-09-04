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
    if len(sys.argv) != 4:
        print 'usage: remote_lat <connect-to> <message-size> <roundtrip-count>'
        sys.exit (1)

    try:
        connect_to = sys.argv [1]
        message_size = int (sys.argv [2])
        roundtrip_count = int (sys.argv [3])
    except (ValueError, OverflowError), e:
        print 'message-size and message-count must be integers'
        sys.exit (1)

    ctx = libpyzmq.Context (1, 1);   
    s = libpyzmq.Socket (ctx, libpyzmq.REQ)
    s.connect (connect_to)

    msg = ''.join ([' ' for n in range (0, message_size)])

    start = datetime.now ()

    for i in range (0, roundtrip_count):
        s.send (msg)
        msg = s.recv ()
        assert len (msg) == message_size

    end = datetime.now ()
    delta = (end - start).microseconds + 1000000 * (end - start).seconds
    latency = float (delta) / roundtrip_count / 2

    print "message size: %.0f [B]" % (message_size, )
    print "roundtrip count: %.0f" % (roundtrip_count, )
    print "mean latency: %.3f [us]" % (latency, )

if __name__ == "__main__":
    main ()
    
