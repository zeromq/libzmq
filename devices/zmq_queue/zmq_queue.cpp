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

class queue
{
public:

    queue (zmq::socket_t& reply, zmq::socket_t& request) :
        xrep (reply),
        xreq (request)
    {
        items [0].socket = reply;
        items [0].fd = 0;
        items [0].events = ZMQ_POLLIN;
        items [0].revents = 0;

        items [1].socket = request;
        items [1].fd = 0;
        items [1].events = ZMQ_POLLIN;
        items [1].revents = 0;

        m_next_request_method = &queue::get_request;
        m_next_response_method = &queue::get_response;
    }

    void run()
    {
        while (true) {
            int rc = zmq::poll (&items [0], 2, -1);
            if (rc < 0)
                break;
            next_request();
            next_response();
        }
    }

private:

    void next_request()
    {
        (this->*m_next_request_method) ();
    }

    void next_response()
    {
        (this->*m_next_response_method) ();
    }

    void get_request()
    {
        if (items [0].revents & ZMQ_POLLIN ) {
            int rc = xrep.recv (&request_msg, ZMQ_NOBLOCK);
            if (!rc)
                return;
            items [0].events &= ~ZMQ_POLLIN;
            items [1].events |= ZMQ_POLLOUT;
            m_next_request_method = &queue::send_request;
        }
    }

    void send_request()
    {
        if (items [1].revents & ZMQ_POLLOUT) {
        int rc = xreq.send (request_msg, ZMQ_NOBLOCK);
        if (!rc) return;
        items [1].events &= ~ZMQ_POLLOUT;
        items [0].events |= ZMQ_POLLIN;
        m_next_request_method = &queue::get_request;
        }
    }

    void get_response()
    {
        if ( items [1].revents & ZMQ_POLLIN ) {
            int rc = xreq.recv (&response_msg, ZMQ_NOBLOCK);
            if (!rc)
                return;
            items [1].events &= ~ZMQ_POLLIN;
            items [0].events |= ZMQ_POLLOUT;
            m_next_response_method = &queue::send_response;
        }
    }

    void send_response()
    {
        if (items [0].revents & ZMQ_POLLOUT) {
            int rc = xrep.send (response_msg, ZMQ_NOBLOCK);
            if (!rc)
                return;
            items [0].events &= ~ZMQ_POLLOUT;
            items [1].events |= ZMQ_POLLIN;
            m_next_response_method = &queue::get_response;
        }
    }

    zmq::socket_t & xrep;
    zmq::socket_t & xreq;
    zmq_pollitem_t items [2];
    zmq::message_t request_msg;
    zmq::message_t response_msg;

    typedef void (queue::*next_method) ();

    next_method m_next_request_method;
    next_method m_next_response_method;

    queue (queue const &);
    void operator = (queue const &);
};

int main (int argc, char *argv [])
{
    if (argc != 2) {
        fprintf (stderr, "usage: zmq_queue <config-file>\n");
        return 1;
    }

    XMLNode root = XMLNode::parseFile (argv [1]);
    if (root.isEmpty ()) {
        fprintf (stderr, "configuration file not found or not an XML file\n");
        return 1;
    }

    if (strcmp (root.getName (), "queue") != 0) {
        fprintf (stderr, "root element in the configuration file should be "
            "named 'queue'\n");
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
    zmq::context_t ctx (1, 1);
    zmq::socket_t in_socket (ctx, ZMQ_XREP);
    zmq::socket_t out_socket (ctx, ZMQ_XREQ);

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

    queue q(in_socket, out_socket);
    q.run();

    return 0;
}
