/*
    Copyright (c) 2007-2015 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __TESTUTIL_HPP_INCLUDED__
#define __TESTUTIL_HPP_INCLUDED__

#include "../include/zmq.h"
#include "../src/stdint.hpp"
#include "platform.hpp"

//  This defines the settle time used in tests; raise this if we
//  get test failures on slower systems due to binds/connects not
//  settled. Tested to work reliably at 1 msec on a fast PC.
#define SETTLE_TIME 10         //  In msec

#undef NDEBUG
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <string>
#include <string.h>

#if defined _WIN32
#   if defined _MSC_VER
#       include <crtdbg.h>
#       pragma warning(disable:4996)
#   endif
#else
#   include <unistd.h>
#   include <signal.h>
#   include <stdlib.h>
#   include <sys/wait.h>
#endif

//  Bounce a message from client to server and back
//  For REQ/REP or DEALER/DEALER pairs only

void
bounce (void *server, void *client)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";

    //  Send message from client to server
    int rc = zmq_send (client, content, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (client, content, 32, 0);
    assert (rc == 32);

    //  Receive message at server side
    char buffer [32];
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (server, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (server, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Send two parts back to client
    rc = zmq_send (server, buffer, 32, ZMQ_SNDMORE);
    assert (rc == 32);
    rc = zmq_send (server, buffer, 32, 0);
    assert (rc == 32);

    //  Receive the two parts at the client side
    rc = zmq_recv (client, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (client, buffer, 32, 0);
    assert (rc == 32);
    //  Check that message is still the same
    assert (memcmp (buffer, content, 32) == 0);
    rc = zmq_getsockopt (client, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);
}

//  Same as bounce, but expect messages to never arrive
//  for security or subscriber reasons.

void
expect_bounce_fail (void *server, void *client)
{
    const char *content = "12345678ABCDEFGH12345678abcdefgh";
    char buffer [32];
    int timeout = 150;

    //  Send message from client to server
    int rc = zmq_setsockopt (client, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_send (client, content, 32, ZMQ_SNDMORE);
    assert ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));
    rc = zmq_send (client, content, 32, 0);
    assert ((rc == 32) || ((rc == -1) && (errno == EAGAIN)));

    //  Receive message at server side (should not succeed)
    rc = zmq_setsockopt (server, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_recv (server, buffer, 32, 0);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);

    //  Send message from server to client to test other direction
    //  If connection failed, send may block, without a timeout
    rc = zmq_setsockopt (server, ZMQ_SNDTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_send (server, content, 32, ZMQ_SNDMORE);
    assert (rc == 32 || (rc == -1 && zmq_errno () == EAGAIN));
    rc = zmq_send (server, content, 32, 0);
    assert (rc == 32 || (rc == -1 && zmq_errno () == EAGAIN));

    //  Receive message at client side (should not succeed)
    rc = zmq_setsockopt (client, ZMQ_RCVTIMEO, &timeout, sizeof (int));
    assert (rc == 0);
    rc = zmq_recv (client, buffer, 32, 0);
    assert (rc == -1);
    assert (zmq_errno () == EAGAIN);
}

//  Receive 0MQ string from socket and convert into C string
//  Caller must free returned string. Returns NULL if the context
//  is being terminated.
char *
s_recv (void *socket) {
    char buffer [256];
    int size = zmq_recv (socket, buffer, 255, 0);
    if (size == -1)
        return NULL;
    if (size > 255)
        size = 255;
    buffer [size] = 0;
    return strdup (buffer);
}

//  Convert C string to 0MQ string and send to socket
int
s_send (void *socket, const char *string) {
    int size = zmq_send (socket, string, strlen (string), 0);
    return size;
}

//  Sends string as 0MQ string, as multipart non-terminal
int
s_sendmore (void *socket, const char *string) {
    int size = zmq_send (socket, string, strlen (string), ZMQ_SNDMORE);
    return size;
}

#define streq(s1,s2)    (!strcmp ((s1), (s2)))
#define strneq(s1,s2)   (strcmp ((s1), (s2)))

const char *SEQ_END = (const char *) 1;

//  Sends a message composed of frames that are C strings or null frames.
//  The list must be terminated by SEQ_END.
//  Example: s_send_seq (req, "ABC", 0, "DEF", SEQ_END);
void s_send_seq (void *socket, ...)
{
    va_list ap;
    va_start (ap, socket);
    const char * data = va_arg (ap, const char *);
    while (true)
    {
        const char * prev = data;
        data = va_arg (ap, const char *);
        bool end = data == SEQ_END;

        if (!prev) {
            int rc = zmq_send (socket, 0, 0, end ? 0 : ZMQ_SNDMORE);
            assert (rc != -1);
        }
        else {
            int rc = zmq_send (socket, prev, strlen (prev)+1, end ? 0 : ZMQ_SNDMORE);
            assert (rc != -1);
        }
        if (end)
            break;
    }
    va_end (ap);
}

//  Receives message a number of frames long and checks that the frames have
//  the given data which can be either C strings or 0 for a null frame.
//  The list must be terminated by SEQ_END.
//  Example: s_recv_seq (rep, "ABC", 0, "DEF", SEQ_END);
void s_recv_seq (void *socket, ...)
{
    zmq_msg_t msg;
    zmq_msg_init (&msg);

    int more;
    size_t more_size = sizeof(more);

    va_list ap;
    va_start (ap, socket);
    const char * data = va_arg (ap, const char *);

    while (true) {
        int rc = zmq_msg_recv (&msg, socket, 0);
        assert (rc != -1);

        if (!data)
            assert (zmq_msg_size (&msg) == 0);
        else
            assert (strcmp (data, (const char *)zmq_msg_data (&msg)) == 0);

        data = va_arg (ap, const char *);
        bool end = data == SEQ_END;

        rc = zmq_getsockopt (socket, ZMQ_RCVMORE, &more, &more_size);
        assert (rc == 0);

        assert (!more == end);
        if (end)
            break;
    }
    va_end (ap);

    zmq_msg_close (&msg);
}


//  Sets a zero linger period on a socket and closes it.
void close_zero_linger (void *socket)
{
    int linger = 0;
    int rc = zmq_setsockopt (socket, ZMQ_LINGER, &linger, sizeof(linger));
    assert (rc == 0 || errno == ETERM);
    rc = zmq_close (socket);
    assert (rc == 0);
}

void setup_test_environment()
{
#if defined _WIN32
#   if defined _MSC_VER
    _set_abort_behavior( 0, _WRITE_ABORT_MSG);
    _CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
    _CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDERR );
#   endif
#else
    // abort test after 60 seconds
    alarm(60);
#endif
#if defined __MVS__
    // z/OS UNIX System Services: Ignore SIGPIPE during test runs, as a
    // workaround for no SO_NOGSIGPIPE socket option.
    signal(SIGPIPE, SIG_IGN);
#endif
}

//  Provide portable millisecond sleep
// http://www.cplusplus.com/forum/unices/60161/    http://en.cppreference.com/w/cpp/thread/sleep_for
void msleep (int milliseconds)
{
#ifdef ZMQ_HAVE_WINDOWS
    Sleep (milliseconds);
#else
    usleep (static_cast <useconds_t> (milliseconds) * 1000);
#endif
}


#endif
