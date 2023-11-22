/* SPDX-License-Identifier: MPL-2.0 */

#include "testutil.hpp"
#include "testutil_unity.hpp"

#if defined ZMQ_HAVE_OPENPGM && defined ZMQ_HAVE_WINDOWS
#include <shlobj_core.h>
#pragma comment(lib, "shell32.lib")
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

SETUP_TEARDOWN_TESTCONTEXT

void test (const char *address)
{
    //  Create a publisher
    void *publisher = test_context_socket (ZMQ_PUB);
    char my_endpoint[MAX_SOCKET_STRING];

    //  Bind publisher
    test_bind (publisher, address, my_endpoint, MAX_SOCKET_STRING);

    //  Create a subscriber
    void *subscriber = test_context_socket (ZMQ_SUB);
    TEST_ASSERT_SUCCESS_ERRNO (zmq_connect (subscriber, my_endpoint));

    //  Subscribe to all messages.
    TEST_ASSERT_SUCCESS_ERRNO (
      zmq_setsockopt (subscriber, ZMQ_SUBSCRIBE, "", 0));

    //  Wait a bit till the subscription gets to the publisher
    msleep (SETTLE_TIME);

    //  Send three messages
    send_string_expect_success (publisher, "test1", 0);
    send_string_expect_success (publisher, "test2", 0);
    send_string_expect_success (publisher, "test3", 0);

    //  Receive the messages
    recv_string_expect_success (subscriber, "test1", 0);
    recv_string_expect_success (subscriber, "test2", 0);
    recv_string_expect_success (subscriber, "test3", 0);

    //  Clean up.
    test_context_socket_close (publisher);
    test_context_socket_close (subscriber);
}

void test_norm ()
{
#if defined ZMQ_HAVE_NORM
    test ("norm://224.0.1.20:6210");
#else
    TEST_IGNORE_MESSAGE ("libzmq without NORM, ignoring test.");
#endif
}

#if defined ZMQ_HAVE_OPENPGM
#if defined ZMQ_HAVE_WINDOWS
int GetAdapterIpAddress (
  _Out_writes_bytes_ (ipAddressBufferSizeBytes) char *ipAddressBuffer,
  size_t ipAddressBufferSizeBytes,
  _Out_writes_bytes_opt_ (adapterNameBufferSizeBytes) char *adapterNameBuffer = nullptr,
  size_t adapterNameBufferSizeBytes = 0)
{
    *ipAddressBuffer = 0;

    if ((adapterNameBuffer != nullptr) && (adapterNameBufferSizeBytes > 0)) {
        *adapterNameBuffer = 0;
    }

    if (ipAddressBufferSizeBytes < 8) {
        return -1;
    }

    //
    // Alocate memory for up to 8 adapters
    //

    ULONG bufferSizeBytes = 8 * sizeof (IP_ADAPTER_INFO);
    void *buffer = malloc (bufferSizeBytes);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO *) buffer;

    //
    // Retrieve information for all adapters
    //

    int result = GetAdaptersInfo (pAdapterInfo, &bufferSizeBytes);

    if (result == ERROR_BUFFER_OVERFLOW) {
        //
        // Buffer was too small
        //

        free (buffer);
        buffer = malloc (bufferSizeBytes);

        if (!buffer) {
            return -1;
        }

        //
        // Try again
        //

        pAdapterInfo = (IP_ADAPTER_INFO *) buffer;
        result = GetAdaptersInfo (pAdapterInfo, &bufferSizeBytes);
    }

    if (result != ERROR_SUCCESS) {
        free (buffer);
        return -1;
    }

    //
    // Find the best(?) Ethernet adapter
    //

    result = -1;
    int bestAdapterScore = 0;

    while (pAdapterInfo && bestAdapterScore < 4) {
        if ((pAdapterInfo->Type == IF_TYPE_ETHERNET_CSMACD)
            || (pAdapterInfo->Type == IF_TYPE_IEEE80211)) {
            char c = pAdapterInfo->IpAddressList.IpAddress.String[0];

            if ((c != 0) && (c != '0')) {
                int currentAdapterScore = 1; // Has IP address!

                if (pAdapterInfo->Type == IF_TYPE_ETHERNET_CSMACD) {
                    ++currentAdapterScore; // Is Ethernet?
                }

                c = pAdapterInfo->GatewayList.IpAddress.String[0];

                if ((c != 0) && (c != '0')) {
                    ++currentAdapterScore; // Has gateway?
                }

                c = pAdapterInfo->DhcpServer.IpAddress.String[0];

                if ((c != 0) && (c != '0')) {
                    ++currentAdapterScore; // Has DHCP server?
                }

                if (currentAdapterScore > bestAdapterScore) {
                    result = 0;
                    bestAdapterScore = currentAdapterScore;

                    memset (ipAddressBuffer, 0, ipAddressBufferSizeBytes);
                    strcpy_s (ipAddressBuffer, ipAddressBufferSizeBytes,
                              pAdapterInfo->IpAddressList.IpAddress.String);

                    if ((adapterNameBuffer != nullptr)
                        && (adapterNameBufferSizeBytes > 0)) {
                        memset (adapterNameBuffer, 0,
                                adapterNameBufferSizeBytes);
                        strncpy_s (adapterNameBuffer,
                                   adapterNameBufferSizeBytes,
                                   pAdapterInfo->Description,
                                   _countof (pAdapterInfo->Description));
                    }
                }
            }
        }

        pAdapterInfo = pAdapterInfo->Next;
    }

    free (buffer);
    return result;
}
#else
#define NETWORK_ADAPTER "eth0"
#endif
#endif

void test_epgm ()
{
#if defined ZMQ_HAVE_OPENPGM
#ifdef ZMQ_HAVE_WINDOWS
    char network[64];
    char ip_address[16];
    TEST_ASSERT_EQUAL_INT (
      0, GetAdapterIpAddress (ip_address, _countof (ip_address)));
    sprintf_s (network, _countof (network), "epgm://%s;224.0.1.20:6211",
               ip_address);
    test (network);
#else
#ifdef NETWORK_ADAPTER
    test ("epgm://" NETWORK_ADAPTER ";224.0.1.20:6211");
#else
    TEST_IGNORE_MESSAGE (
      "libzmq with OpenPGM, but NETWORK_ADAPTER wasn't set, ignoring test.");
#endif
#endif
#else
    TEST_IGNORE_MESSAGE ("libzmq without OpenPGM, ignoring test.");
#endif
}

void test_pgm ()
{
#if defined ZMQ_HAVE_OPENPGM
#ifdef ZMQ_HAVE_WINDOWS
    if (!IsUserAnAdmin ()) {
        TEST_IGNORE_MESSAGE (
          "libzmq with OpenPGM, but user is not an admin, ignoring test.");
    } else {
        char network[64];
        char ip_address[16];
        TEST_ASSERT_EQUAL_INT (
          0, GetAdapterIpAddress (ip_address, _countof (ip_address)));
        sprintf_s (network, _countof (network), "pgm://%s;224.0.1.20:6212",
                   ip_address);
        test (network);
    }
#else
#ifdef NETWORK_ADAPTER
    test ("pgm://" NETWORK_ADAPTER ";224.0.1.20:6212");
#else
    TEST_IGNORE_MESSAGE (
      "libzmq with OpenPGM, but NETWORK_ADAPTER wasn't set, ignoring test.");
#endif
#endif
#else
    TEST_IGNORE_MESSAGE ("libzmq without OpenPGM, ignoring test.");
#endif
}

void test_tcp ()
{
    test ("tcp://localhost:6213");
}

void test_ipc ()
{
    test ("ipc://test_pubsub");
}

void test_inproc ()
{
    test ("inproc://test_pubsub");
}

void test_ws ()
{
#if defined ZMQ_HAVE_WS
    test ("ws://localhost:6214");
#else
    TEST_IGNORE_MESSAGE ("libzmq without WebSockets, ignoring test.");
#endif
}

void test_wss ()
{
#if defined ZMQ_HAVE_WSS
    test ("wss://localhost:6214");
#else
    TEST_IGNORE_MESSAGE ("libzmq without WSS WebSockets, ignoring test.");
#endif
}

int ZMQ_CDECL main ()
{
    setup_test_environment ();

    UNITY_BEGIN ();
    RUN_TEST (test_norm);
    RUN_TEST (test_epgm);
    RUN_TEST (test_pgm);
    RUN_TEST (test_tcp);
    RUN_TEST (test_ipc);
    RUN_TEST (test_inproc);
    RUN_TEST (test_ws);
    RUN_TEST (test_wss);
    return UNITY_END ();
}
