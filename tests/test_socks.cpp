/*
    Copyright (c) 2019 Contributors as noted in the AUTHORS file

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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "testutil.hpp"
#include "testutil_unity.hpp"


SETUP_TEARDOWN_TESTCONTEXT

void recvall (int sock_fd, char *buffer, int len)
{
    int res;
    int total = 0;
    while (len - total > 0) {
        res = recv (sock_fd, buffer + total, len - total, 0);
        if (res == -1)
            fprintf (stderr, "socks_server: error receiving %d bytes: %d %d\n",
                     len, res, errno);
        TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
        TEST_ASSERT (res != 0);
        total += res;
    }
    TEST_ASSERT (total == len);
}

int recvonce (int sock_fd, char *buffer, int len)
{
    int res;
    res = recv (sock_fd, buffer, len, 0);
    if (res == -1)
        fprintf (stderr, "socks_server: error receiving bytes: %d %d\n", res,
                 errno);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
    return res;
}

void sendall (int sock_fd, char *buffer, int len)
{
    int res;
    int total = 0;
    while (len - total > 0) {
        res = send (sock_fd, buffer + total, len - total, 0);
        if (res == -1)
            fprintf (stderr, "socks_server: error sending %d bytes: %d %d\n",
                     len, res, errno);
        TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
        TEST_ASSERT (res != 0);
        total += res;
    }
}

int remote_connect (int socket, uint32_t addr, uint16_t port)
{
    int res;
    struct sockaddr_in ip4addr;
    ip4addr.sin_family = AF_INET;
    ip4addr.sin_addr.s_addr = htonl (addr);
    ip4addr.sin_port = htons (port);
    res = connect (socket, (struct sockaddr *) &ip4addr, sizeof ip4addr);
    return res;
}

void *setup_socks_server (char *socks_server_address,
                          int socks_server_address_len)
{
    fprintf (stderr, "socks_server: setup socks server\n");
    int server_fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    TEST_ASSERT_NOT_EQUAL (-1, server_fd);
    int flag = 1;
    int res;
    res = setsockopt (server_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof (int));
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
    struct sockaddr_in saddr = bind_bsd_socket (server_fd);
    int nbytes = snprintf (socks_server_address, socks_server_address_len,
                           "127.0.0.1:%d", ntohs (saddr.sin_port));
    TEST_ASSERT (nbytes >= 0 && nbytes < socks_server_address_len);
    fprintf (stderr, "socks_server: bound to: tcp://%s\n",
             socks_server_address);
    return (void *) (intptr_t) server_fd;
}

void socks_server_task (void *socks_server,
                        const char *username,
                        const char *password,
                        int max_client_connect)
{
    int server_fd = (int) (intptr_t) socks_server;
    fprintf (stderr, "socks_server: starting server thread\n");

    int res;
    res = listen (server_fd, max_client_connect);
    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);

    int auth_method;
    if (username == NULL || username[0] == '\0') {
        auth_method = 0x0; /* No auth */
    } else {
        auth_method = 0x2; /* Basic auth */
        if (password == NULL)
            password = "";
    }

    int count = 0;
    while (count < max_client_connect) {
        int client = -1;
        do {
            char buffer[4096];
            fprintf (stderr, "socks_server: waiting for connection\n");
            client = accept (server_fd, NULL, NULL);
            TEST_ASSERT_SUCCESS_RAW_ERRNO (client);
            count++;
            fprintf (stderr, "socks_server: accepted client connection %d/%d\n",
                     count, max_client_connect);

            /* Greetings [version, nmethods, methods...]. */
            recvall (client, buffer, 2);
            TEST_ASSERT (buffer[0] == 0x5);
            int nmethods = buffer[1];
            int method = 0xff;
            recvall (client, buffer, nmethods);
            for (int i = 0; i < nmethods; i++) {
                if (buffer[i] == auth_method)
                    method = auth_method;
            }
            fprintf (stderr, "socks_server: received greetings\n");

            /* Greetings response [version, method]. */
            buffer[0] = 0x5;
            buffer[1] = method;
            sendall (client, buffer, 2);
            fprintf (stderr,
                     "socks_server: answered greetings (method: 0x%x)\n",
                     method);

            if (method == 0xff)
                break; /* Out of client connection */

            if (method == 0x2) {
                int len;
                int err = 0;
                recvall (client, buffer, 1);
                if (buffer[0] != 0x1) {
                    err = 1;
                } else {
                    recvall (client, buffer, 1);
                    len = (unsigned char) buffer[0];
                    recvall (client, buffer, len);
                    buffer[len] = '\0';
                    if (strcmp (username, buffer) != 0) {
                        fprintf (stderr,
                                 "socks_server: error on username check: '%s', "
                                 "expected: '%s'\n",
                                 buffer, username);
                        err = 1;
                    }
                    recvall (client, buffer, 1);
                    len = (unsigned char) buffer[0];
                    recvall (client, buffer, len);
                    buffer[len] = '\0';
                    if (strcmp (password, buffer) != 0) {
                        fprintf (stderr,
                                 "socks_server: error on password check: '%s', "
                                 "expected: '%s'\n",
                                 buffer, password);
                        err = 1;
                    }
                }
                fprintf (stderr, "socks_server: received credentials\n");
                buffer[0] = 0x1;
                buffer[1] = err;
                sendall (client, buffer, 2);
                fprintf (stderr,
                         "socks_server: answered credentials (err: 0x%x)\n",
                         err);
                if (err != 0)
                    break; /* Out of client connection. */
            }

            /* Request [version, cmd, rsv, atype, dst.addr, dst.port */
            /* Test only tcp connect on top of IPV4 */
            recvall (client, buffer, 4);
            TEST_ASSERT (buffer[0] == 0x5);
            TEST_ASSERT (buffer[1] == 0x1); /* CONNECT cmd */
            TEST_ASSERT (buffer[2] == 0x0); /* reserved, ensure we send 0 */
            fprintf (stderr,
                     "socks_server: received command (cmd: %d, atype: %d)\n",
                     buffer[1], buffer[3]);
            /* IPv4 ADDR & PORT */
            uint32_t naddr = 0, bind_naddr = 0;
            uint16_t nport = 0, bind_nport = 0;
            int remote = -1;
            int err = 0;
            int request_atype = buffer[3];
            if (request_atype == 0x1) /* ATYPE IPv4 */ {
                recvall (client, (char *) &naddr, 4);
                fprintf (stderr,
                         "socks_server: received address (addr: 0x%x)\n",
                         ntohl (naddr));
            } else if (request_atype == 0x3) /* ATYPE DOMAINNAME */ {
                int len;
                recvall (client, buffer, 1);
                len = (unsigned char) buffer[0];
                recvall (client, buffer, len);
                buffer[len] = '\0';
                fprintf (stderr,
                         "socks_server: received domainname (hostname: %s)\n",
                         buffer);
                /* For the test we support static resolution of
                   hostname "somedomainnmame.org" to localhost */
                if (strcmp ("somedomainname.org", buffer) == 0) {
                    naddr = htonl (0x7f000001); /* 127.0.0.1 */
                } else {
                    err = 0x4; /* Host unreachable */
                }
            } else if (request_atype == 0x4) {
                /* For the test we simulate IPV6 connection request ::1, but connect to IPv4 localhost */
                unsigned char nipv6local[16] = {0};
                nipv6local[15] = 1;
                recvall (client, buffer, 16);
                fprintf (stderr,
                         "socks_server: received ipv6 address (buffer:");
                for (int i = 0; i < 16; i++)
                    fprintf (stderr, " 0x%x", (unsigned char) buffer[i]);
                fprintf (stderr, ")\n");
                if (memcmp (buffer, nipv6local, 16) == 0) {
                    naddr = htonl (0x7f000001); /* 127.0.0.1 */
                } else {
                    err = 0x4; /* Host unreachable */
                }
            } else {
                err = 0x8; /* ATYPE not supported */
            }
            recvall (client, (char *) &nport, 2);
            fprintf (stderr, "socks_server: received port (port: %d)\n",
                     ntohs (nport));
            if (err == 0) {
                fprintf (stderr, "socks_server: trying to connect to %x:%d\n",
                         ntohl (naddr), ntohs (nport));
                remote = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
                res = remote_connect (remote, ntohl (naddr), ntohs (nport));
                if (res != 0) {
                    err = 0x5; /* Connection refused */
                } else {
                    struct sockaddr_in ip4addr;
                    socklen_t len = sizeof (ip4addr);
                    res =
                      getsockname (remote, (struct sockaddr *) &ip4addr, &len);
                    TEST_ASSERT_SUCCESS_RAW_ERRNO (res);
                    fprintf (stderr,
                             "socks_server: connected and bound at: %x:%d\n",
                             ntohl (ip4addr.sin_addr.s_addr),
                             ntohs (ip4addr.sin_port));
                    bind_naddr = ip4addr.sin_addr.s_addr;
                    bind_nport = ip4addr.sin_port;
                }
            }

            /* Reply request */
            buffer[0] = 0x5;
            buffer[1] = err;
            buffer[2] = 0;
            buffer[3] = request_atype;
            sendall (client, buffer, 4);
            if (request_atype == 0x1) /* ATYPE IPv4 */ {
                sendall (client, (char *) &bind_naddr, 4);
            } else if (request_atype == 0x3) {
                /* This is just for testing reply with a hostname,
                   normally a resolved address is passed in return to connect. */
                buffer[0] = strlen ("localhost");
                sendall (client, buffer, 1);
                strcpy (buffer, "localhost");
                sendall (client, buffer, strlen ("localhost"));
            } else if (request_atype == 0x4) {
                /* We simulate a bind to ::1, though the actual connection is IPv4 */
                char nipv6local[16] = {0};
                nipv6local[15] = 1;
                sendall (client, nipv6local, sizeof nipv6local);
            }
            sendall (client, (char *) &bind_nport, 2);
            fprintf (stderr, "socks_server: replied to request (err: 0x%x)\n",
                     err);
            if (err != 0)
                break; /* Out of client connection. */

            /* Communication loop */
            zmq_pollitem_t items[] = {
              {NULL, client, ZMQ_POLLIN, 0},
              {NULL, remote, ZMQ_POLLIN, 0},
            };
            fprintf (stderr,
                     "socks_server: waiting for input (client fd: %d, remote "
                     "fd: %d)\n",
                     client, remote);
            while (1) {
                if (client == -1 || remote == -1)
                    break;
                if (zmq_poll (items, 2, -1) < 0)
                    break;
                int nbytes;
                for (int i = 0; i < 2; i++) {
                    if ((items[i].revents & ZMQ_POLLIN) == 0)
                        continue;
                    fprintf (stderr, "socks_server: ready to read from fd %d\n",
                             items[i].fd);
                    int write_fd, read_fd = items[i].fd;
                    if (read_fd == client) {
                        write_fd = remote;
                    } else {
                        write_fd = client;
                    }
                    nbytes = recvonce (read_fd, buffer, sizeof buffer);
                    fprintf (stderr, "socks_server: read returned: %d\n",
                             nbytes);
                    if (nbytes == 0 || nbytes == -1) {
                        /* End of stream or error */
                        if (read_fd == client) {
                            close (client);
                            client = -1;
                        }
                        if (read_fd == remote) {
                            close (remote);
                            remote = -1;
                        }
                        break;
                    }
                    sendall (write_fd, buffer, nbytes);
                }
            }
            if (remote != -1) {
                close (remote);
                remote = -1;
            }
            fprintf (stderr, "socks_server: closed remote connection %d/%d\n",
                     count, max_client_connect);
        } while (0); /* Client socket scope. */
        if (client != -1) {
            close (client);
            client = -1;
        }
        fprintf (stderr, "socks_server: closed client connection %d/%d\n",
                 count, max_client_connect);
    }
    close (server_fd);
    fprintf (stderr, "socks_server: closed server\n");
}

void socks_server_no_auth (void *socks_server)
{
    socks_server_task (socks_server, NULL, NULL, 1);
}

void socks_server_no_auth_delay (void *socks_server)
{
    fprintf (stderr, "socks_server: delay no auth socks server start\n");
    // Enough delay to have client connecting before proxy listens
    msleep (SETTLE_TIME * 10);
    socks_server_task (socks_server, NULL, NULL, 1);
}

void socks_server_basic_auth (void *socks_server)
{
    socks_server_task (socks_server, "someuser", "somepass", 1);
}

void socks_server_basic_auth_delay (void *socks_server)
{
    fprintf (stderr, "socks_server: delay basic auth socks server start\n");
    // Enough delay to have client connecting before proxy listens
    msleep (SETTLE_TIME * 10);
    socks_server_task (socks_server, "someuser", "somepass", 1);
}

void socks_server_basic_auth_no_pass (void *socks_server)
{
    socks_server_task (socks_server, "someuser", NULL, 1);
}

void *setup_push_server (char *connect_address, int connect_address_size)
{
    int res;
    const char *bind_address = "tcp://127.0.0.1:*";
    void *push = test_context_socket (ZMQ_PUSH);
    res = zmq_bind (push, bind_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    size_t len = connect_address_size;
    res = zmq_getsockopt (push, ZMQ_LAST_ENDPOINT, connect_address, &len);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "push_server: bound to: %s\n", connect_address);
    return push;
}

void *setup_pull_client (const char *connect_address, const char *socks_proxy)
{
    int res;
    void *pull = test_context_socket (ZMQ_PULL);
    if (socks_proxy != NULL) {
        res = zmq_setsockopt (pull, ZMQ_SOCKS_PROXY, socks_proxy,
                              strlen (socks_proxy));
        TEST_ASSERT_SUCCESS_ERRNO (res);
        fprintf (stderr, "pull_client: use socks proxy: tcp://%s\n",
                 socks_proxy);
    }
    res = zmq_connect (pull, connect_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "pull_client: connected to: %s\n", connect_address);
    return pull;
}

#ifdef ZMQ_BUILD_DRAFT_API
void *setup_pull_client_with_auth (const char *connect_address,
                                   const char *socks_proxy,
                                   const char *username,
                                   const char *password)
{
    int res;
    void *pull = test_context_socket (ZMQ_PULL);

    if (socks_proxy != NULL) {
        res = zmq_setsockopt (pull, ZMQ_SOCKS_PROXY, socks_proxy,
                              strlen (socks_proxy));
        TEST_ASSERT_SUCCESS_ERRNO (res);
        fprintf (stderr, "pull_client: use socks proxy: tcp://%s\n",
                 socks_proxy);
    }

    res = zmq_setsockopt (pull, ZMQ_SOCKS_USERNAME, username,
                          username == NULL ? 0 : strlen (username));
    TEST_ASSERT_SUCCESS_ERRNO (res);

    res = zmq_setsockopt (pull, ZMQ_SOCKS_PASSWORD, password,
                          password == NULL ? 0 : strlen (password));
    TEST_ASSERT_SUCCESS_ERRNO (res);

    res = zmq_connect (pull, connect_address);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    fprintf (stderr, "pull_client: connected to: %s\n", connect_address);
    return pull;
}
#endif

void communicate (void *push, void *pull)
{
    fprintf (stderr, "push_server: sending 2 messages\n");
    s_send_seq (push, "ABC", SEQ_END);
    s_send_seq (push, "DEF", SEQ_END);

    fprintf (stderr, "pull_client: receiving 2 messages\n");
    s_recv_seq (pull, "ABC", SEQ_END);
    s_recv_seq (pull, "DEF", SEQ_END);
}

void test_socks_no_socks (void)
{
    char connect_address[MAX_SOCKET_STRING];

    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client (connect_address, NULL);
    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);
}

void test_socks (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client (connect_address, socks_server_address);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_delay (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client (connect_address, socks_server_address);
    void *thread = zmq_threadstart (&socks_server_no_auth_delay, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_domainname (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];
    char connect_address_hostname[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    // Will be resolved by the proxy test server to 127.0.0.1
    strcpy (connect_address_hostname, "tcp://somedomainname.org");
    strcat (connect_address_hostname, strrchr (connect_address, ':'));
    void *pull =
      setup_pull_client (connect_address_hostname, socks_server_address);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_ipv6 (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];
    char connect_address_hostname[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    // Will be resolved by the proxy test server to 127.0.0.1
    strcpy (connect_address_hostname, "tcp://::1");
    strcat (connect_address_hostname, strrchr (connect_address, ':'));
    void *pull =
      setup_pull_client (connect_address_hostname, socks_server_address);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_ipv6_sb (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];
    char connect_address_hostname[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    // Will be resolved by the proxy test server to 127.0.0.1
    strcpy (connect_address_hostname, "tcp://[::1]");
    strcat (connect_address_hostname, strrchr (connect_address, ':'));
    void *pull =
      setup_pull_client (connect_address_hostname, socks_server_address);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_bind_before_connect (void)
{
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];
    char socks_address_bind_before_connect[MAX_SOCKET_STRING * 2];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    // Will do a bind before connect when connecting to proxy
    strcpy (socks_address_bind_before_connect, "127.0.0.1:0;");
    strcat (socks_address_bind_before_connect, socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull =
      setup_pull_client (connect_address, socks_address_bind_before_connect);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
}

void test_socks_basic_auth (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (
      connect_address, socks_server_address, "someuser", "somepass");
    void *thread = zmq_threadstart (&socks_server_basic_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_delay (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (
      connect_address, socks_server_address, "someuser", "somepass");
    void *thread = zmq_threadstart (&socks_server_basic_auth_delay, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_empty_user (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (connect_address,
                                              socks_server_address, "", NULL);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_null_user (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (connect_address,
                                              socks_server_address, NULL, NULL);
    void *thread = zmq_threadstart (&socks_server_no_auth, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_empty_pass (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (
      connect_address, socks_server_address, "someuser", "");
    void *thread = zmq_threadstart (&socks_server_basic_auth_no_pass, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}

void test_socks_basic_auth_null_pass (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char socks_server_address[MAX_SOCKET_STRING];
    char connect_address[MAX_SOCKET_STRING];

    void *socks =
      setup_socks_server (socks_server_address, sizeof socks_server_address);
    void *push = setup_push_server (connect_address, sizeof connect_address);
    void *pull = setup_pull_client_with_auth (
      connect_address, socks_server_address, "someuser", NULL);
    void *thread = zmq_threadstart (&socks_server_basic_auth_no_pass, socks);

    communicate (push, pull);

    test_context_socket_close_zero_linger (push);
    test_context_socket_close_zero_linger (pull);

    zmq_threadclose (thread);
#else
    TEST_IGNORE_MESSAGE (
      "libzmq without DRAFT support, ignoring socks basic auth test");
#endif
}


void test_string_opt_ok (const char *msg, int opt, const char *value)
{
    int res;
    void *sub = test_context_socket (ZMQ_SUB);
    fprintf (stderr, "test_string_opt_ok: testing %s\n", msg);
    res = zmq_setsockopt (sub, opt, value, strlen (value));
    TEST_ASSERT_SUCCESS_ERRNO (res);
    char buffer[1024];
    size_t res_len = (size_t) sizeof buffer;
    res = zmq_getsockopt (sub, opt, buffer, &res_len);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    TEST_ASSERT_EQUAL (strlen (value) + 1, res_len);
    TEST_ASSERT (strcmp (buffer, value) == 0);
    test_context_socket_close_zero_linger (sub);
}

void test_opt_ok (const char *msg,
                  int opt,
                  const char *value,
                  size_t len,
                  const char *expected_value,
                  size_t expected_len)
{
    int res;
    void *sub = test_context_socket (ZMQ_SUB);
    fprintf (stderr, "test_opt_ok: testing %s\n", msg);
    res = zmq_setsockopt (sub, opt, value, len);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    char buffer[1024];
    size_t res_len = (size_t) sizeof buffer;
    res = zmq_getsockopt (sub, opt, buffer, &res_len);
    TEST_ASSERT_SUCCESS_ERRNO (res);
    TEST_ASSERT_EQUAL (expected_len + 1, res_len);
    TEST_ASSERT_EQUAL (expected_len, strlen (buffer));
    TEST_ASSERT (strncmp (buffer, expected_value, expected_len) == 0);
    test_context_socket_close_zero_linger (sub);
}

void test_opt_invalid (const char *msg, int opt, const char *value, int len)
{
    int res;
    void *sub = test_context_socket (ZMQ_SUB);
    fprintf (stderr, "test_opt_invalid: testing %s\n", msg);
    res = zmq_setsockopt (sub, opt, value, len);
    TEST_ASSERT_FAILURE_ERRNO (EINVAL, res);
    test_context_socket_close_zero_linger (sub);
}

void test_socks_proxy_options (void)
{
    // NULL is equivalent to not set and returns empty string
    test_opt_ok ("NULL proxy", ZMQ_SOCKS_PROXY, NULL, 0, "", 0);
    test_string_opt_ok ("valid proxy", ZMQ_SOCKS_PROXY, "somehost:1080");
    // Empty value not allowed for proxy server
    test_opt_invalid ("empty proxy", ZMQ_SOCKS_PROXY, "", 0);
}

void test_socks_userpass_options (void)
{
#ifdef ZMQ_BUILD_DRAFT_API
    char buffer[1024];
    for (int i = 0; i < (int) sizeof buffer; i++) {
        buffer[i] = 'a' + i % 26;
    }

    // NULL is equivalent to not-set or ""
    test_opt_ok ("NULL username", ZMQ_SOCKS_USERNAME, NULL, 0, "", 0);
    // Empty value is allowed for username, means no authentication
    test_string_opt_ok ("empty username", ZMQ_SOCKS_USERNAME, "");
    test_string_opt_ok ("valid username", ZMQ_SOCKS_USERNAME, "someuser");
    test_opt_ok ("255 bytes username", ZMQ_SOCKS_USERNAME, buffer, 255, buffer,
                 255);
    test_opt_invalid ("too long username", ZMQ_SOCKS_USERNAME, buffer, 256);

    // NULL is equivalent to not-set or ""
    test_opt_ok ("NULL password", ZMQ_SOCKS_PASSWORD, NULL, 0, "", 0);
    // Empty value allowed for password
    test_string_opt_ok ("empty password", ZMQ_SOCKS_PASSWORD, "");
    test_string_opt_ok ("valid password", ZMQ_SOCKS_PASSWORD, "someuser");
    test_opt_ok ("255 bytes password", ZMQ_SOCKS_PASSWORD, buffer, 255, buffer,
                 255);
    test_opt_invalid ("too long password", ZMQ_SOCKS_PASSWORD, buffer, 256);
#else
    TEST_IGNORE_MESSAGE ("libzmq without DRAFT support, ignoring socks setopt "
                         "username/password test");
#endif
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_socks_proxy_options);
    RUN_TEST (test_socks_userpass_options);
    RUN_TEST (test_socks_no_socks);
    RUN_TEST (test_socks);
    RUN_TEST (test_socks_delay);
    RUN_TEST (test_socks_domainname);
    RUN_TEST (test_socks_ipv6);
    RUN_TEST (test_socks_ipv6_sb);
    RUN_TEST (test_socks_bind_before_connect);
    RUN_TEST (test_socks_basic_auth);
    RUN_TEST (test_socks_basic_auth_delay);
    RUN_TEST (test_socks_basic_auth_empty_user);
    RUN_TEST (test_socks_basic_auth_null_user);
    RUN_TEST (test_socks_basic_auth_empty_pass);
    RUN_TEST (test_socks_basic_auth_null_pass);
    return UNITY_END ();
}
