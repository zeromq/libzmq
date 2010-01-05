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
    if (argc != 3) {
        fprintf (stderr, "usage: prompt <address> <username>\n");
        return 1;
    }

    //  Retrieve command line arguments
    const char *address = argv [1];
    const char *username = argv [2];

    //  Initialise 0MQ infrastructure.
    zmq::context_t ctx (1, 1);
    zmq::socket_t s (ctx, ZMQ_PUB);
    s.connect (address);

    //  Prepare a message buffer. Place username at the beginning
    //  of the message.
    char textbuf [1024];
#ifdef _MSC_VER
    _snprintf_s (textbuf, sizeof (textbuf), sizeof (textbuf), "%s: ",
        username);
#else
    snprintf (textbuf, sizeof (textbuf), "%s: ", username);
#endif
    size_t prefixsz = strlen (textbuf);
    char *text = textbuf + prefixsz;
    
    while (true) {

        //  Let user type the enter the message text.
        char *rcc = fgets (text, sizeof (textbuf) - prefixsz, stdin);
        assert (rcc);

        //  Create the message (terminating zero is part of the message).
        zmq::message_t msg (strlen (textbuf) + 1);
        memcpy (msg.data (), textbuf, msg.size ());

        //  Send the message
        s.send (msg);
    }
}
