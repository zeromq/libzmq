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

public class Message {
    static {
        System.loadLibrary("jzmq");
    }

    /**
     * Class constructor.
     */
    public Message () {
        construct ();
    }

    public Message (byte [] payload) {
        constructWithData (payload);
    }

    /**
     * Get message payload.
     */
    public native byte [] getMsgPayload ();

    /**
     * Get message type.
     */
    public native int getMsgType ();

    /**
     * Get low-level message handler.
     */
    public long getMsgHandle () {
        return msgHandle;
    }

    /** Initialize the JNI interface */
    protected native void construct ();

    protected native void constructWithData (byte [] payload);

    /** Free resources used by JNI driver. */
    protected native void finalize ();

    /** Opaque data used by JNI driver. */
    private long msgHandle;
}

