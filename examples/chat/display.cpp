/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <zmq.hpp>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main (int argc, const char *argv [])
{
    //  Check the command line syntax.
    if (argc != 2) {
        fprintf (stderr, "usage: display <address>\n");
        return 1;
    }

    //  Retrieve command line arguments
    const char *address = argv [1];

    //  Initialise 0MQ infrastructure.
    zmq::context_t ctx (1, 1);
    zmq::socket_t s (ctx, ZMQ_SUB);
    s.setsockopt (ZMQ_SUBSCRIBE, "", 0);
    s.connect (address);
    
    while (true) {

        //  Get a message and print it to the console.
        zmq::message_t msg;
        s.recv (&msg);
        fprintf (stdout, "%s", (char*) msg.data ());
        fflush (stdout);
    }
}
