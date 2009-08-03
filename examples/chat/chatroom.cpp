/*
    Copyright (c) 2007-2009 FastMQ Inc.

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

#include <time.h>
#include <string.h>
#include <iostream>

using namespace std;

#include <zmq.hpp>

int main (int argc, const char *argv [])
{
    //  Check the command line syntax
    if (argc != 3) {
        cerr << "usage: chatroom <in-interface> <out-interface>" << endl;
        return 1;
    }

    //  Retrieve command line arguments
    const char *in_interface = argv [1];
    const char *out_interface = argv [2];

    //  Initialise 0MQ infrastructure
    zmq::context_t ctx (1, 1);

    //  Create two sockets. One for receiving messages from 'propmt'
    //  applications, one for sending messages to 'display' applications
    zmq::socket_t in_socket (ctx, ZMQ_SUB);
    in_socket.bind (in_interface);
    zmq::socket_t out_socket (ctx, ZMQ_PUB);
    out_socket.bind (out_interface);

    while (true) {

        //  Get a message
        zmq::message_t in_message;
        in_socket.recv (&in_message);

        //  Get the current time. Replace the newline character at the end
        //  by space character.
        char timebuf [256];
        time_t current_time;
        time (&current_time);
        snprintf (timebuf, 256, "%s", ctime (&current_time));
        timebuf [strlen (timebuf) - 1] = ' ';

        //  Create and fill in the message
        zmq::message_t out_message (strlen (timebuf) + in_message.size ());
        char *data = (char*) out_message.data ();
        memcpy (data, timebuf, strlen (timebuf));
        data += strlen (timebuf);
        memcpy (data, in_message.data (), in_message.size ());

        //  Send the message
        out_socket.send (out_message);
    }
}
