/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

    public static final int ZMQ_MAX_VSM_SIZE = 30;

    public static final int ZMQ_GAP = 1;

    public static final int ZMQ_DELIMITER = 31;

    public static final int ZMQ_NOBLOCK = 1;

    public static final int ZMQ_NOFLUSH = 2;

    public static final int ZMQ_P2P = 0;

    public static final int ZMQ_PUB = 1;

    public static final int ZMQ_SUB = 2;

    /**
     * Class constructor.
     *
     * @param context
     * @param type
     */
    public Socket (Context context, int type) {
        ctx = context;
        construct (context, type);
    }

    /**
     * Set the high watermark on the socket.
     *
     * @param hwm high watermark.
     */
    public native void setHwm (long hwm);

    /**
     * Set the low watermark on the socket.
     *
     * @param lwm low watermark.
     */
    public native void setLwm (long lwm);

    /**
     * Set swap size.
     *
     * @param swap_size swap size.
     */
    public native void setSwap (long swap_size);

    /**
     * Set reception mask.
     *
     * @param mask mask.
     */
    public native void setMask (long mask);

    /**
     * Set affinity.
     *
     * @param affinity
     */
    public native void setAffinity (long affinity);

    /**
     * Set identity.
     *
     * @param identity
     */
    public native void setIdentity (String identity);

    /**
     * @param addr
     */
    public native void bind (String addr);

    /**
     * Connect.
     *
     * @param addr
     */
    public native void connect (String addr);

    /**
     * Send.
     *
     * @param message
     * @param block
     */
    public native int send (Message msg, long flags);

    /**
     * Flush all messages sent with flush flag false down the stream.
     */
    public native void flush ();

    /**
     * Receive message.
     *
     * @param block
     * @return
     */
    public native Message recv (long flags);

    /** Initialize JNI driver */
    protected native void construct (Context context, int type);

    /** Free all resources used by JNI driver. */
    protected native void finalize ();

    /** Keep reference to ZMQ context so it is not garbage collected */
    private Context ctx;

    /** Opaque data used by JNI driver. */
    private long socketHandle;

}
