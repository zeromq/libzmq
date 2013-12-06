/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include <string.h>

#include <sstream>

#include "testutil.hpp"

static void zap_handler (void *handler)
{
    //  Process ZAP requests forever
    while (true) {
        char *version = s_recv (handler);
        if (!version)
            break;          //  Terminating
        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *identity = s_recv (handler);
        char *mechanism = s_recv (handler);

        assert (streq (version, "1.0"));
        assert (streq (mechanism, "NULL"));
        
        if (streq (domain, "creds")) {
            std::ostringstream buf;
            buf << "localhost:" << getuid () << ":" << getgid () << ":";
#           ifdef ZMQ_HAVE_SO_PEERCRED
            buf << getpid ();
#           endif
            assert (streq (address, buf.str ().c_str ()));
        } else
            assert (streq (address, "localhost"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);
        s_sendmore (handler, "200");
        s_sendmore (handler, "OK");
        s_sendmore (handler, "anonymous");
        s_send     (handler, "");

        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
    }
    zmq_close (handler);
}

static void run_test (bool with_creds)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Spawn ZAP handler
    //  We create and bind ZAP socket in main thread to avoid case
    //  where child thread does not start up fast enough.
    void *handler = zmq_socket (ctx, ZMQ_REP);
    assert (handler);
    int rc = zmq_bind (handler, "inproc://zeromq.zap.01");
    assert (rc == 0);
    void *zap_thread = zmq_threadstart (&zap_handler, handler);

    void *sb = zmq_socket (ctx, ZMQ_PAIR);
    assert (sb);

    void *sc = zmq_socket (ctx, ZMQ_PAIR);
    assert (sc);

    //  Now use the right domain, the test must pass
    if (with_creds) {
        rc = zmq_setsockopt (sb, ZMQ_ZAP_DOMAIN, "creds", 5);
        assert (rc == 0);
        int ipc_creds = 1;
        rc = zmq_setsockopt (sb, ZMQ_ZAP_IPC_CREDS, &ipc_creds, sizeof (int));
        assert (rc == 0);
    } else {
        rc = zmq_setsockopt (sb, ZMQ_ZAP_DOMAIN, "none", 4);
        assert (rc == 0);
        int ipc_creds = 1;
        size_t size = sizeof (int);
        rc = zmq_getsockopt (sb, ZMQ_ZAP_IPC_CREDS, &ipc_creds, &size);
        assert (rc == 0);
        assert (ipc_creds == 0);
    }

    rc = zmq_bind (sb, "ipc://@/tmp/test");
    assert (rc == 0);

    rc = zmq_connect (sc, "ipc://@/tmp/test");
    assert (rc == 0);
        
    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);
    rc = zmq_close (sb);
    assert (rc == 0);

    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    //  Wait until ZAP handler terminates.
    zmq_threadclose (zap_thread);
}

int main (void)
{
    setup_test_environment();

    run_test(false);
    run_test(true);

    return 0 ;
}

