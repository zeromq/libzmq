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
        print 'usage: local_lat <bind-to> <message-size> <roundtrip-count>'
        sys.exit (1)

    try:
        bind_to = sys.argv [1]
        message_size = int (sys.argv [2])
        roundtrip_count = int (sys.argv [3])
    except (ValueError, OverflowError), e:
        print 'message-size and roundtrip-count must be integers'
        sys.exit (1)

    ctx = libpyzmq.Context (1, 1);   
    s = libpyzmq.Socket (ctx, libpyzmq.REP)
    s.bind (bind_to)

    for i in range (0, roundtrip_count):
        msg = s.recv ()
        assert len (msg) == message_size
        s.send (msg)

    time.sleep (1)

if __name__ == "__main__":
    main ()
