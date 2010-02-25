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

public class Socket {
    static {
        System.loadLibrary("jzmq");
    }

    public static final int NOBLOCK = 1;
    public static final int NOFLUSH = 2;

    public static final int P2P = 0;
    public static final int PUB = 1;
    public static final int SUB = 2;
    public static final int REQ = 3;
    public static final int REP = 4;
    public static final int XREQ = 5;
    public static final int XREP = 6;
    public static final int UPSTREAM = 7;
    public static final int DOWNSTREAM = 8;

    public static final int HWM = 1;
    public static final int LWM = 2;
    public static final int SWAP = 3;
    public static final int AFFINITY = 4;
    public static final int IDENTITY = 5;
    public static final int SUBSCRIBE = 6;
    public static final int UNSUBSCRIBE = 7;
    public static final int RATE = 8;
    public static final int RECOVERY_IVL = 9;
    public static final int MCAST_LOOP = 10;
    public static final int SNDBUF = 11;
    public static final int RCVBUF = 12;

    /**
     * Class constructor.
     *
     * @param context a 0MQ context previously created.
     * @param type the socket type.
     */
    public Socket (Context context, int type) {
        construct (context, type);
    }

    /**
     * Set the socket option value, given as a long.
     *
     * @param option ID of the option to set.
     * @param optval value (as a long) to set the option to.
     */
    public native void setsockopt (int option, long optval);

    /**
     * Set the socket option value, given as a String.
     *
     * @param option ID of the option to set.
     * @param optval value (as a String) to set the option to.
     */
    public native void setsockopt (int option, String optval);

    /**
     * Bind to network interface. Start listening for new connections.
     *
     * @param addr the endpoint to bind to.
     */
    public native void bind (String addr);

    /**
     * Connect to remote application.
     *
     * @param addr the endpoint to connect to.
     */
    public native void connect (String addr);

    /**
     * Send a message.
     *
     * @param msg the message to send, as an array of bytes.
     * @param flags the flags to apply to the send operation.
     * @return true if send was successful, false otherwise.
     */
    public native boolean send (byte [] msg, long flags);

    /**
     * Flush the messages down the stream.
     */
    public native void flush ();

    /**
     * Receive a message.
     *
     * @param flags the flags to apply to the receive operation.
     * @return the message received, as an array of bytes; null on error.
     */
    public native byte [] recv (long flags);

    /** Initialize the JNI interface */
    protected native void construct (Context context, int type);

    /** Free all resources used by JNI interface. */
    protected native void finalize ();

    /**
     * Get the underlying socket handle.
     * This is private because it is only accessed from JNI, where
     * Java access controls are ignored.
     *
     * @return the internal 0MQ socket handle.
     */
    private long getSocketHandle () {
        return socketHandle;
    }

    /** Opaque data used by JNI driver. */
    private long socketHandle;
}
