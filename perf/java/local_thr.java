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

import org.zmq.*;

class local_thr
{
    public static void main (String [] args)
    {
        if (args.length != 3) {
            System.out.println ("usage: local_thr <bind-to> " +
                "<message size> <message count>");
            return;
        }

        String bindTo = args [0];
        long messageSize = Integer.parseInt (args [1]);
        long messageCount = Integer.parseInt (args [2]);

        org.zmq.Context ctx = new org.zmq.Context (1, 1, 0);

        org.zmq.Socket s = new org.zmq.Socket (ctx, org.zmq.Socket.SUB);

        s.setsockopt (org.zmq.Socket.SUBSCRIBE , "");

        //  Add your socket options here.
        //  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

        s.bind (bindTo);

        byte [] data = s.recv (0);
        assert (data.length == messageSize);

        long start = System.currentTimeMillis ();

        for (int i = 1; i != messageCount; i ++) {
            data = s.recv (0);
            assert (data.length == messageSize);
        }

        long end = System.currentTimeMillis ();

        long elapsed = (end - start) * 1000;
        if (elapsed == 0)
            elapsed = 1;

        long throughput = messageCount * 1000000 / elapsed;
        double megabits = (double) (throughput * messageSize * 8) / 1000000;

        System.out.println ("message size: " + messageSize + " [B]");
        System.out.println ("message count: " + messageCount);
        System.out.println ("mean throughput: " + throughput + "[msg/s]");
        System.out.println ("mean throughput: " + megabits + "[Mb/s]");        
    }
}
