/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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

#include "zmq.h"
#include "zmq_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <sys/time.h>

#define		ZMSG 1
#define		DATA 0

typedef struct US_TIMER US_TIMER;

struct US_TIMER{

    struct timeval  time_was;
    struct timeval  time_now;
};
/*  Records the current timer state
*/
void tm_init( US_TIMER *t){

    if( gettimeofday( &t->time_now, NULL) < 0){ perror( "d_timer_init()");}

    t->time_was = t->time_now;

}

/*  Returns the time passed in microsecond precision in seconds since last init
    of timer.
*/
float tm_secs( US_TIMER *t){

    register float seconds;

    if( gettimeofday( &t->time_now, NULL) < 0){ perror( "d_timer_init()");}

    seconds = ( ((float)( t->time_now.tv_sec - t->time_was.tv_sec)) +
             (((float)( t->time_now.tv_usec - t->time_was.tv_usec)) / 1000000.0));

    t->time_was = t->time_now;

    return( seconds);
}

const char *bind_to;
int message_count = 1000;
int message_size = 1024;
int threads = 1;
int workers = 1;
int sndbuflen = 128*256;
int rcvbuflen = 128*256;
int flow = ZMQ_PULL;
int rec = DATA;

void my_free (void *data, void *hint)
{
   // free (data);
}

int main (int argc, char *argv [])
{
    US_TIMER timer;
    void *ctx;
    void *s;
    int rc;
    int i;
	void *buf = NULL;

    if (argc != 9) {
        printf ("usage: local_thr <bind-to> <message-size> <message-count> <SND buffer> <RCV buffer> <flow (PUSH/PULL)> <rec (ZMSG/DATA)> <zmq-threads>\n");
        return 1;
    }

    bind_to = argv [1];
    message_size = atoi (argv [2]);
    message_count = atoi (argv [3]);
	sndbuflen = atoi (argv [4]);
	rcvbuflen = atoi (argv [5]);
    if( !strcmp( argv [6], "PUSH")){
        flow = ZMQ_PUSH;
    }
    if( !strcmp( argv [6], "PULL")){
        flow = ZMQ_PULL;
    }
    if( !strcmp( argv [7], "ZMSG")){
        rec = ZMSG;
    }
    if( !strcmp( argv [7], "DATA")){
        rec = DATA;
    }
    threads = atoi (argv [8]);

	if( !(buf = malloc( message_size))){ perror("malloc"); return -1;}

    ctx = zmq_ctx_new ();
    if (!ctx) {
        printf ("error in zmq_ctx_new: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_ctx_set ( ctx, ZMQ_IO_THREADS, threads);
    if (rc) {
        printf ("error in zmq_ctx_set: %s\n", zmq_strerror (errno));
        return -1;
    }

    s = zmq_socket (ctx, flow);
    if (!s) {
        printf ("error in zmq_socket: %s\n", zmq_strerror (errno));
        return -1;
    }

    //  Add your socket options here.
    //  For example ZMQ_RATE, ZMQ_RECOVERY_IVL and ZMQ_MCAST_LOOP for PGM.

	size_t rcvbuflenlen = (size_t)sizeof rcvbuflen;
	size_t sndbuflenlen = (size_t)sizeof sndbuflen;

	rc = zmq_setsockopt (s, ZMQ_RCVBUF, &rcvbuflen, rcvbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_setsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }
	rc = zmq_setsockopt (s, ZMQ_SNDBUF, &sndbuflen, sndbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_setsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }

	sndbuflen = 1;
	rc = zmq_setsockopt (s, ZMQ_DELAY_ATTACH_ON_CONNECT, &sndbuflen, sndbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_setsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }

	sndbuflen = 2;
	rc = zmq_setsockopt (s, ZMQ_SNDHWM, &sndbuflen, sndbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_setsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }

	sndbuflen = 2;
	rc = zmq_setsockopt (s, ZMQ_RCVHWM, &sndbuflen, sndbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_setsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }


	rc = zmq_getsockopt (s, ZMQ_RCVBUF, &rcvbuflen, &rcvbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_getsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }
	rc = zmq_getsockopt (s, ZMQ_SNDBUF, &sndbuflen, &sndbuflenlen);
    if (rc != 0) {
        printf ("error in zmq_getsockopt: %s\n", zmq_strerror (errno));
        return -1;
    }

	printf("RCVBUF=%d KB SNDBUF=%d KB adjusted\n", rcvbuflen/1024, sndbuflen/1024);

	printf("Threads: %d\n", zmq_ctx_get( ctx, ZMQ_IO_THREADS));

    rc = zmq_bind (s, bind_to);
    if (rc != 0) {
        printf ("error in zmq_bind: %s\n", zmq_strerror (errno));
        return -1;
    }

	if( !(buf = malloc( message_size))){ perror("malloc"); return -1;}

	printf("%sING %s...\n", flow == ZMQ_PUSH ? "PUSH":"PULL", rec ? "ZMQ_MSG":"DATA");

    tm_init( &timer);

    if( flow == ZMQ_PULL){

		if( rec == ZMSG){

        zmq_msg_t msg;

        rc = zmq_msg_init (&msg);
        if (rc != 0) {
            printf ("error in zmq_msg_init: %s\n", zmq_strerror (errno));
            return -1;
        }
        for (i = 0; i != message_count; i++) {
            rc = zmq_msg_recv (&msg, s, 0);
            if (rc < 0) {
                printf ("error in zmq_recv: %s\n", zmq_strerror (errno));
                return -1;
            }
        }
        rc = zmq_msg_close (&msg);
        if (rc != 0) {
            printf ("error in zmq_msg_close: %s\n", zmq_strerror (errno));
            return -1;
        }}

		else{

        for (i = 0; i != message_count; i++) {
            rc = zmq_recv( s, buf, message_size, 0);
            if (rc < 0) {
                printf ("error in zmq_recv: %s\n", zmq_strerror (errno));
                return -1;
            }
        }}
    }
    else{

		if( rec == ZMSG){

        zmq_msg_t msg;

        for (i = 0; i != message_count; i++) {

            rc = zmq_msg_init_data (&msg, buf, message_size, NULL, NULL);
            if (rc != 0) {
                printf ("error in zmq_msg_init_data: %s\n", zmq_strerror (errno));
                return -1;
            }

            rc = zmq_msg_send( &msg, s, 0);
            if (rc < 0) {
                printf ("error in zmq_send: %s\n", zmq_strerror (errno));
                return -1;
            }
        }}
	
	
		else{
        for (i = 0; i != message_count; i++){
            rc = zmq_send( s, buf, message_size, 0);
            if (rc < 0) {
                printf ("error in zmq_send: %s\n", zmq_strerror (errno));
            	return -1;
            }
        }}
    }

    float secs = tm_secs( &timer);
    float total = (((float) message_count) * ((float) message_size)) / (1024.0*1024.0*1024.0);

    printf ("Message size: %d KBytes, time: %f secs\n", (int) message_size/1024, secs);
    printf ("%sed %.3f GB @ %.3f GB/s\n", (flow == ZMQ_PULL) ? "Pull":"Push", total, total/secs);


    rc = zmq_close (s);
    if (rc != 0) {
        printf ("error in zmq_close: %s\n", zmq_strerror (errno));
        return -1;
    }

    rc = zmq_term (ctx);
    if (rc != 0) {
        printf ("error in zmq_term: %s\n", zmq_strerror (errno));
        return -1;
    }

    if( buf) free( buf);

    return 0;
}
