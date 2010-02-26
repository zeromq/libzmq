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

package org.zmq;

public class Poller {
    static {
        System.loadLibrary("jzmq");
    }

    public static final int POLLIN = 1;
    public static final int POLLOUT = 2;
    public static final int POLLERR = 4;

    /**
     * Class constructor.
     *
     * @param context a 0MQ context previously created.
     */
    public Poller (Context context, int size) {
        this.context = context;
        this.size = size;
        this.next = 0;

        this.socket = new Socket[size];
        this.event = new short[size];
        this.revent = new short[size];

        for (int i = 0; i < size; ++i) {
            this.event[i] = (POLLIN | POLLOUT | POLLERR);
        }
    }

    public int register (Socket socket) {
        if (next >= size)
            return -1;
        this.socket[next] = socket;
        return next++;
    }
    
    public long getTimeout () {
        return this.timeout;
    }
    
    public void setTimeout (long timeout) {
        this.timeout = timeout;
    }

    public int getSize () {
        return this.size;
    }

    public int getNext () {
        return this.next;
    }

    /**
     * Issue a poll call.
     * @return how many objects where signalled by poll().
     */
    public long poll () {
        if (size <= 0 || next <= 0)
            return 0;

        for (int i = 0; i < next; ++i) {
            revent[i] = 0;
        }

        return run_poll(next, socket, event, revent, timeout);
    }

    public boolean pollin(int index) {
        return poll_mask(index, POLLIN);
    }

    public boolean pollout(int index) {
        return poll_mask(index, POLLOUT);
    }

    public boolean pollerr(int index) {
        return poll_mask(index, POLLERR);
    }

    /**
     * Issue a poll call on the specified 0MQ sockets.
     *
     * @param socket an array of 0MQ Socket objects to poll.
     * @param event an array of short values specifying what to poll for.
     * @param revent an array of short values with the results.
     * @param timeout the maximum timeout in microseconds.
     * @return how many objects where signalled by poll().
     */
    private native long run_poll(int count,
                                 Socket[] socket,
                                 short[] event,
                                 short[] revent,
                                 long timeout);

    /**
     * Check whether a specific mask was signalled by latest poll call.
     *
     * @param index the index indicating the socket.
     * @param mask a combination of POLLIN, POLLOUT and POLLERR.
     * @return true if specific socket was signalled as specified.
     */
    private boolean poll_mask(int index, int mask) {
        if (mask <= 0 || index < 0 || index >= next)
            return false;
        return (revent[index] & mask) > 0;
    }

    private Context context = null;
    private long timeout = 0;
    private int size = 0;
    private int next = 0;
    private Socket[] socket = null;
    private short[] event = null;
    private short[] revent = null;
}
