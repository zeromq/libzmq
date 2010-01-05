#
#    Copyright (c) 2007-2010 iMatix Corporation
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
import time
import libpyzmq

def main ():
    if len (sys.argv) != 4:
        print 'usage: local_thr <bind-to> <message-size> <message-count>'
        sys.exit (1)

    try:
        bind_to = sys.argv [1]
        message_size = int (sys.argv [2])
        message_count = int (sys.argv [3])
    except (ValueError, OverflowError), e:
        print 'message-size and message-count must be integers'
        sys.exit (1)

    ctx = libpyzmq.Context (1, 1);   
    s = libpyzmq.Socket (ctx, libpyzmq.SUB)

    s.setsockopt (libpyzmq.SUBSCRIBE , "*");

    #  Add your socket options here.
    #  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

    s.bind (bind_to)

    msg = s.recv ()
    assert len (msg) == message_size

    start = time.clock ()

    for i in range (1, message_count):
        msg = s.recv ()
        assert len (msg) == message_size
 
    end = time.clock ()

    elapsed = (end - start) * 1000000
    if elapsed == 0:
    	elapsed = 1
    throughput = (1000000.0 * float (message_count)) / float (elapsed)
    megabits = float (throughput * message_size * 8) / 1000000

    print "message size: %.0f [B]" % (message_size, )
    print "message count: %.0f" % (message_count, )
    print "mean throughput: %.0f [msg/s]" % (throughput, )
    print "mean throughput: %.3f [Mb/s]" % (megabits, )

if __name__ == "__main__":
    main ()
