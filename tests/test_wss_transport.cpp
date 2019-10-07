/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

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

#include <string.h>
#include "testutil.hpp"
#include "testutil_unity.hpp"

SETUP_TEARDOWN_TESTCONTEXT

#ifdef ZMQ_WSS_CERT_PEM
const char *key =
  "-----BEGIN PRIVATE KEY-----\n"
  "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\n"
  "NX3nbNTMU7FmPoUgF8jm+hS9ecfWVf9c\n"
  "-----END PRIVATE KEY-----";

const char *cert =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIFjzCCA3egAwIBAgIUMVYFTVoSsqvKRSfeaBZfD0WlDhkwDQYJKoZIhvcNAQEL\n"
  "BQAwVzELMAkGA1UEBhMCWFgxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEcMBoGA1UE\n"
  "CgwTRGVmYXVsdCBDb21wYW55IEx0ZDETMBEGA1UEAwwKemVyb21xLm9yZzAeFw0x\n"
  "OTEwMDExMTEyMjVaFw0xOTEwMzExMTEyMjVaMFcxCzAJBgNVBAYTAlhYMRUwEwYD\n"
  "VQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0RlZmF1bHQgQ29tcGFueSBMdGQx\n"
  "EzARBgNVBAMMCnplcm9tcS5vcmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\n"
  "AoICAQCrXKFPWrRqbdNoltLhL8YYva5au+f3ntrOybMJmhWJdkXL1DxC5F6XDNNz\n"
  "YET+WTrBpwfY1yX6OYZwBpnh9K/Kb00wJTkd6MxeqEV2eTp7iAt/BzmWNXIausyk\n"
  "XuBuWq+M+oFXXlTbgFXLlqV8/B+1klxFuSjNxbDN+IBLgz7k86F2sAa6RoZ2jHWs\n"
  "DmmnPHHUX7XZbs8IgBcwL112Z7QvX/0x/JQFn5ulxWlkvYsgunjebSaR2gQeKFZ8\n"
  "f3E8J6bgUk2INEafKndzRX/hpZ0Q0g0R4DPTcSDSXdRb6do5Fgre/qhiKkRHqQPY\n"
  "1aIZTG0byG60vtDacJ+NGM21hP0BtGxg+/ES1TdMSdmz9LaCGaV3ydoEC6qz+eXW\n"
  "Id5jL82D7ywft679GQtmq8/iOwb6Z5sz76Xu8aiBtwYWrW3tlRfvPS/0nxHYLPhQ\n"
  "1RJZKWW0EFUtar7aizde3fKDkUI1CvWUfLN5SrvA3TMHQCsbqXNRKMXRBW4M0jel\n"
  "z1cy67l9IMa5vVzzjvxCdIyHjE1k5MzKhQgCihDYn0QdEuEbGjOE3sU/g22K2t33\n"
  "QvDGGnwH3yoNvjgLQ/IEwcixrPm1cxQYmYhYrt5MPn4sNxVw3ne/LgRfRdIyCmGN\n"
  "MN7QHG0s1ciTqxaKJPUyUDAoqOy9t17oKk0HVmp6YjzY2NEIkwIDAQABo1MwUTAd\n"
  "BgNVHQ4EFgQUjU31StK8ffuKYL6IfYmCuHvgzr4wHwYDVR0jBBgwFoAUjU31StK8\n"
  "ffuKYL6IfYmCuHvgzr4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
  "AgEAPv4vOG5C3HXlPe+fRPqtR28cpjNddJWgFRkYxp5vntN6mVrswkUzD/a8sZ6t\n"
  "ly4bGgQPGjshCOLvlRQera+XxBMB2kafWL+2YiRsLRl0eCeTY04Rn3MUVFwuet9/\n"
  "gk1Xh3j5dMPh3oAo9ZVT+/rYc9376YDYm5IPxZXPEA/huXc8iK8NXCWoUvkYMimC\n"
  "x3dzyyW2hp3mJEjOQS8jSayZfsS/UjhV0KYwDPKdjUbHYR7hGqLrEXjIBz5ee8On\n"
  "9olSYvZ7/TGIzZTSZXYUx9mbq763OTMjRGLTVj+fD0rsa5Toz4TXsOjzppS8cqL9\n"
  "kzNmUG6qVpO4Q/+wKgfeUy6HqxGSxFqH6W0QdQP1rTtBTayhSdHppH5Dupx+7S4p\n"
  "pmaL6k535DlFnFQZjIXIqGnP/oXwIjn5la66EqdU0fPLprH4sqVXAM032swyHFop\n"
  "RIM6NV8u0fRjQXqyJDktMXPUYNaV+rwXbtImjVaoelK8LvSwzKc6NLEEHgsa3HMO\n"
  "6z93LtCk+ocCrAABQor1S/fAq5TpL6btaUzAi2qfj5yWgZZnt7LkxLp+tHXtfif+\n"
  "E/XAbpLYzkzTYi50IgEBkS1sjT5IOK9Yr0al2tDcQFGpS25SOz7BhCfnj3+MBD//\n"
  "m4Y13hEvpYRBDnfhXCvwD9/wd6Xq1wA+lueDpwWbrfriTJo=\n"
  "-----END CERTIFICATE-----";

void test_roundtrip ()
{
    void *sb = test_context_socket (ZMQ_REP);
    zmq_setsockopt (sb, ZMQ_WSS_CERT_PEM, cert, strlen (cert));
    zmq_setsockopt (sb, ZMQ_WSS_KEY_PEM, key, strlen (key));
    TEST_ASSERT_SUCCESS_ERRNO (zmq_bind (sb, "wss://*:5556/roundtrip"));

    void *sc = test_context_socket (ZMQ_REQ);
    zmq_setsockopt (sc, ZMQ_WSS_TRUST_PEM, cert, strlen (cert));
    zmq_setsockopt (sc, ZMQ_WSS_HOSTNAME, "zeromq.org", strlen ("zeromq.org"));
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_connect (sc, "wss://127.0.0.1:5556/roundtrip"));

    bounce (sb, sc);

    test_context_socket_close (sc);
    test_context_socket_close (sb);
}

int main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_roundtrip);
    return UNITY_END ();
}
#else
int main ()
{
    printf ("WSS unavailable, skipping test\n");
    return 77;
}
#endif
