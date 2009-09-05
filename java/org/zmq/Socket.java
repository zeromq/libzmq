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

public class Socket
{

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

    /**
     * Class constructor.
     *
     * @param context
     * @param type
     */
    public Socket (Context context, int type) {
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
     * Bind to network interface. Start listening for new connections.
     *
     * @param addr
     */
    public native void bind (String addr);

    /**
     * Connect to remote application.
     *
     * @param addr
     */
    public native void connect (String addr);

    /**
     * Send the message.
     *
     * @param msg
     * @param flags
     */
    public native boolean send (byte [] msg, long flags);

    /**
     * Flush the messages down the stream.
     */
    public native void flush ();

    /**
     * Receive message.
     *
     * @param flags
     * @return
     */
    public native byte [] recv (long flags);

    /** Initialize JNI driver */
    protected native void construct (Context context, int type);

    /** Free all resources used by JNI driver. */
    protected native void finalize ();

    /** Opaque data used by JNI driver. */
    private long socketHandle;

}
