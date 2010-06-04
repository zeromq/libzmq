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

#include "../../include/zmq.hpp"
#include "../../foreign/xmlParser/xmlParser.cpp"

int main (int argc, char *argv [])
{
    if (argc != 2) {
        fprintf (stderr, "usage: zmq_forwarder <config-file>\n");
        return 1;
    }

    XMLNode root = XMLNode::parseFile (argv [1]);
    if (root.isEmpty ()) {
        fprintf (stderr, "configuration file not found or not an XML file\n");
        return 1;
    }

    if (strcmp (root.getName (), "forwarder") != 0) {
        fprintf (stderr, "root element in the configuration file should be "
            "named 'forwarder'\n");
        return 1;
    }

    XMLNode in_node = root.getChildNode ("in");
    if (in_node.isEmpty ()) {
        fprintf (stderr, "'in' node is missing in the configuration file\n");
        return 1;
    }

    XMLNode out_node = root.getChildNode ("out");
    if (out_node.isEmpty ()) {
        fprintf (stderr, "'out' node is missing in the configuration file\n");
        return 1;
    }

    //  TODO: make the number of I/O threads configurable.
    zmq::context_t ctx (1);
    zmq::socket_t in_socket (ctx, ZMQ_SUB);
    in_socket.setsockopt (ZMQ_SUBSCRIBE, "", 0);
    zmq::socket_t out_socket (ctx, ZMQ_PUB);

    int n = 0;
    while (true) {
        XMLNode bind = in_node.getChildNode ("bind", n);
        if (bind.isEmpty ())
            break;
        const char *addr = bind.getAttribute ("addr");
        if (!addr) {
            fprintf (stderr, "'bind' node is missing 'addr' attribute\n");
            return 1;
        }
        in_socket.bind (addr);
        n++;
    }

    n = 0;
    while (true) {
        XMLNode connect = in_node.getChildNode ("connect", n);
        if (connect.isEmpty ())
            break;
        const char *addr = connect.getAttribute ("addr");
        if (!addr) {
            fprintf (stderr, "'connect' node is missing 'addr' attribute\n");
            return 1;
        }
        in_socket.connect (addr);
        n++;
    }

    n = 0;
    while (true) {
        XMLNode bind = out_node.getChildNode ("bind", n);
        if (bind.isEmpty ())
            break;
        const char *addr = bind.getAttribute ("addr");
        if (!addr) {
            fprintf (stderr, "'bind' node is missing 'addr' attribute\n");
            return 1;
        }
        out_socket.bind (addr);
        n++;
    }

    n = 0;
    while (true) {
        XMLNode connect = out_node.getChildNode ("connect", n);
        if (connect.isEmpty ())
            break;
        const char *addr = connect.getAttribute ("addr");
        if (!addr) {
            fprintf (stderr, "'connect' node is missing 'addr' attribute\n");
            return 1;
        }
        out_socket.connect (addr);
        n++;
    }

    zmq::device (ZMQ_FORWARDER, in_socket, out_socket);

    return 0;
}
