/*
    Copyright (c) 2007-2014 Contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "testutil.hpp"

/// Initialize a zeromq message with a given null-terminated string
#define ZMQ_PREPARE_STRING(msg, data, size) \
zmq_msg_init(&msg) && printf("zmq_msg_init: %s\n", zmq_strerror(errno)); \
zmq_msg_init_size (&msg, size + 1) && printf("zmq_msg_init_size: %s\n",zmq_strerror(errno)); \
memcpy(zmq_msg_data(&msg), data, size + 1);

int publicationsReceived = 0;
bool isSubscribed = false;

int main(int, char**) {
    setup_test_environment();
    void* context = zmq_ctx_new();
    void* pubSocket;
    void* subSocket;

    (pubSocket = zmq_socket(context, ZMQ_XPUB))         || printf("zmq_socket: %s\n", zmq_strerror(errno));
    (subSocket = zmq_socket(context, ZMQ_SUB))          || printf("zmq_socket: %s\n", zmq_strerror(errno));
    zmq_setsockopt(subSocket, ZMQ_SUBSCRIBE, "foo", 3)  && printf("zmq_setsockopt: %s\n",zmq_strerror(errno));
  
    zmq_bind(pubSocket, "inproc://someInProcDescriptor") && printf("zmq_bind: %s\n", zmq_strerror(errno));
    //zmq_bind(pubSocket, "tcp://127.0.0.1:30010") && printf("zmq_bind: %s\n", zmq_strerror(errno));
  
    int more;
    size_t more_size = sizeof(more);
    int iteration = 0;
  
    while (1) {
        zmq_pollitem_t items [] = {
            { subSocket, 0, ZMQ_POLLIN, 0 }, // read publications
            { pubSocket, 0, ZMQ_POLLIN, 0 }, // read subscriptions
        };
        int rc = zmq_poll (items, 2, 100);
    
        if (items [1].revents & ZMQ_POLLIN) {
            while (1) {
                zmq_msg_t msg;
                zmq_msg_init (&msg);
                zmq_msg_recv (&msg, pubSocket, 0);
                char* buffer = (char*)zmq_msg_data(&msg);

                if (buffer[0] == 0) {
                    assert(isSubscribed);
                    isSubscribed = false;
                } 
                else {
                    assert(!isSubscribed);
                    isSubscribed = true;
                }

                zmq_getsockopt (pubSocket, ZMQ_RCVMORE, &more, &more_size);
                zmq_msg_close (&msg);

                if (!more)
                    break;      //  Last message part
            }
        }

        if (items[0].revents & ZMQ_POLLIN) {
            while (1) {
                zmq_msg_t msg;
                zmq_msg_init (&msg);
                zmq_msg_recv (&msg, subSocket, 0);
                zmq_getsockopt (subSocket, ZMQ_RCVMORE, &more, &more_size);
                zmq_msg_close (&msg);
        
                if (!more) {
                    publicationsReceived++;
                    break;      //  Last message part
                }
            }
        }
        if (iteration == 1) {
            zmq_connect(subSocket, "inproc://someInProcDescriptor") && printf("zmq_connect: %s\n", zmq_strerror(errno));
            //zmq_connect(subSocket, "tcp://127.0.0.1:30010") && printf("zmq_connect: %s\n", zmq_strerror(errno));
        }
        if (iteration == 4) {
            zmq_disconnect(subSocket, "inproc://someInProcDescriptor") && printf("zmq_disconnect(%d): %s\n", errno, zmq_strerror(errno));
            //zmq_disconnect(subSocket, "tcp://127.0.0.1:30010") && printf("zmq_disconnect: %s\n", zmq_strerror(errno));
        }
        if (iteration > 4 && rc == 0)
            break;
        
        zmq_msg_t channelEnvlp;
        ZMQ_PREPARE_STRING(channelEnvlp, "foo", 3);
        zmq_msg_send (&channelEnvlp, pubSocket, ZMQ_SNDMORE) >= 0 || printf("zmq_msg_send: %s\n",zmq_strerror(errno));
        zmq_msg_close(&channelEnvlp) && printf("zmq_msg_close: %s\n",zmq_strerror(errno));

        zmq_msg_t message;
        ZMQ_PREPARE_STRING(message, "this is foo!", 12);
        zmq_msg_send (&message, pubSocket, 0) >= 0 || printf("zmq_msg_send: %s\n",zmq_strerror(errno));
        zmq_msg_close(&message) && printf("zmq_msg_close: %s\n",zmq_strerror(errno));

        iteration++;
    }
    assert(publicationsReceived == 3);
    assert(!isSubscribed);

    zmq_close(pubSocket) && printf("zmq_close: %s", zmq_strerror(errno));
    zmq_close(subSocket) && printf("zmq_close: %s", zmq_strerror(errno));
  
    zmq_ctx_term(context);
    return 0;
}

