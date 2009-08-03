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

#include <string.h>
#include <string>
#include <iostream>

using namespace std;

#include <zmq.hpp>

int main (int argc, const char *argv [])
{
    //  Check the command line syntax.
    if (argc != 3) {
        cerr << "usage: prompt <chatroom-in-address> <user name>" << endl;
        return 1;
    }

    //  Retrieve command line arguments
    const char *chatroom_in_address = argv [1];
    const char *user_name = argv [2];

    //  Initialise 0MQ infrastructure and connect to the chatroom.
    zmq::context_t ctx (1, 1);
    zmq::socket_t s (ctx, ZMQ_PUB);
    s.connect (chatroom_in_address);

    while (true) {

        //  Allow user to input the message text. Prepend it by user name.
        char textbuf [1024];
        char *rcc = fgets (textbuf, sizeof (textbuf), stdin);
        assert (rcc);
        string text (user_name);
        text = text + ": " + textbuf;

        //  Create the message (terminating zero is part of the message)
        zmq::message_t message (text.size () + 1);
        memcpy (message.data (), text.c_str (), text.size () + 1);

        //  Send the message
        s.send (message);
    }
}
