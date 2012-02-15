/*
    Copyright (c) 2011 iMatix Corporation
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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

#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "../include/zmq.h"
#include "../include/zmq_utils.h"

#define THREAD_COUNT 30
#define NMESSAGES 20

struct thread_data_t 
{
  int thread_index;
  void *socket;
  pthread_t pthr;
};

extern "C" 
{
  static void *source(void *client_data)
  {
      // Wait a bit until all threads created and subscriber is ready
      zmq_sleep (1);  // Seconds

      // Our thread number and socket.
      thread_data_t *td = (thread_data_t *) client_data;

      // Buffer for messages.
      char buffer[20];
      memset (buffer, 0, 20);

      // Send messages.
      for (int i = 0; i < NMESSAGES; ++i)
      {
        sprintf(buffer,"Th %02d count %02d", td->thread_index, i);   
        int rc = zmq_send (td->socket, buffer, 20, 0);
        assert (rc == 20);
      }
      return 0;
  }
}


int main (int argc, char *argv [])
{
    fprintf (stderr, "test_ts_context running...\n");

    // Make a thread safe context.
    void *ctx = zmq_init_thread_safe (1);
    assert (ctx);

    //  Create a publisher.
    void *pub = zmq_socket (ctx, ZMQ_PUB);
    assert (pub);
    int rc = zmq_bind (pub, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Create a subscriber.
    void *sub = zmq_socket (ctx, ZMQ_SUB);
    assert (sub);
    rc = zmq_connect (sub, "tcp://127.0.0.1:5560");
    assert (rc == 0);

    //  Subscribe to all messages.
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);

    thread_data_t threads [THREAD_COUNT];
    
    // Create workers.
    for(int i = 0; i < THREAD_COUNT; ++i)
    {
        threads [i].thread_index = i;
        threads [i].socket = pub;
        rc = pthread_create(&threads[i].pthr, NULL, source, threads+i);
        assert (rc == 0);
    }

    // Gather all the Messages.
    char buff [20];
    for(int i= 1; i<=THREAD_COUNT * NMESSAGES; ++i)
    {
        rc = zmq_recv (sub, buff, 20, 0);
        //fprintf (stderr, "%d/%d: %s\n",i,THREAD_COUNT * NMESSAGES, buff); // debug it
        assert (rc >= 0);
    }

    // Wait for worker death.
    for(int i = 0; i < THREAD_COUNT; ++i)
    {
        rc = pthread_join(threads[i].pthr, NULL);
        assert (rc == 0);
    }

    //  Clean up.
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);
    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}
