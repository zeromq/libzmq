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

public class Context {
    static {
        System.loadLibrary("jzmq");
    }

    /**
     * Class constructor.
     *
     * @param appThreads maximum number of application threads.
     * @param ioThreads size of the threads pool to handle I/O operations.
     */
    public Context (int appThreads, int ioThreads) {
        construct (appThreads, ioThreads);
    }

    /**
     * Internal function. Do not use directly!
     */
    public native long createSocket (int type);

    /** Initialize the JNI interface */
    protected native void construct (int appThreads, int ioThreads);

    /** Free resources used by JNI driver. */
    protected native void finalize ();

    /** Opaque data used by JNI driver. */
    private long contextHandle;
}
