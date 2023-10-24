/* SPDX-License-Identifier: MPL-2.0 */

/*  *************************************************************************
    NOTE to contributors. This file comprises the principal public contract
    for ZeroMQ API users. Any change to this file supplied in a stable
    release SHOULD not break existing applications.
    In practice this means that the value of constants must not change, and
    that old values may not be reused for new constants.
    *************************************************************************
*/

#ifndef __ZMQ_H_INCLUDED__
#define __ZMQ_H_INCLUDED__

/*  Version macros for compile-time API version detection                     */
#define ZMQ_VERSION_MAJOR 4
#define ZMQ_VERSION_MINOR 3
#define ZMQ_VERSION_PATCH 6

#define ZMQ_MAKE_VERSION(major, minor, patch)                                  \
    ((major) *10000 + (minor) *100 + (patch))
#define ZMQ_VERSION                                                            \
    ZMQ_MAKE_VERSION (ZMQ_VERSION_MAJOR, ZMQ_VERSION_MINOR, ZMQ_VERSION_PATCH)

#ifdef __cplusplus
extern "C" {
#endif

#if !defined _WIN32_WCE
#include <errno.h>
#endif
#include <stddef.h>
#include <stdio.h>

/* Include Microsoft SAL header, or no-nothing macros depending on platform  */

#include "zmq_sal.h"

/*  Handle DSO symbol visibility                                             */

#if defined ZMQ_NO_EXPORT
#define ZMQ_LINKAGE
#else
#if defined _WIN32
#if defined ZMQ_STATIC
#define ZMQ_LINKAGE
#elif defined DLL_EXPORT
#define ZMQ_LINKAGE __declspec(dllexport)
#else
#define ZMQ_LINKAGE __declspec(dllimport)
#endif
#else
#if defined __SUNPRO_C || defined __SUNPRO_CC
#define ZMQ_LINKAGE __global
#elif (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#define ZMQ_LINKAGE __attribute__ ((visibility ("default")))
#else
#define ZMQ_LINKAGE
#endif
#endif
#endif

#define ZMQ_EXPORT_IMPL(__returntype__)                                        \
    _Check_return_ _Success_ (return == 0) __returntype__
#define ZMQ_EXPORT(__returntype__) ZMQ_LINKAGE ZMQ_EXPORT_IMPL (__returntype__)

#define ZMQ_EXPORT_VOID_IMPL void
#define ZMQ_EXPORT_VOID ZMQ_LINKAGE ZMQ_EXPORT_VOID_IMPL

#define ZMQ_EXPORT_VOID_PTR_IMPL void *
#define ZMQ_EXPORT_VOID_PTR ZMQ_LINKAGE ZMQ_EXPORT_VOID_PTR_IMPL

#define ZMQ_EXPORT_PTR_IMPL(__returntype__, __underlyingtype__)                \
    _Must_inspect_result_ _Success_ (return != NULL)                           \
      _Ret_writes_bytes_ (sizeof (__underlyingtype__)) __returntype__
#define ZMQ_EXPORT_PTR(__returntype__, __underlyingtype__)                     \
    ZMQ_LINKAGE ZMQ_EXPORT_PTR_IMPL (__returntype__, __underlyingtype__)

#define ZMQ_EXPORT_BUF_SIZE_IMPL(__returntype__, __underlyingsize__)           \
    _Must_inspect_result_ _Success_ (return != NULL)                           \
      _Ret_writes_bytes_ (__underlyingsize__) __returntype__
#define ZMQ_EXPORT_BUF_SIZE(__returntype__, __underlyingsize__)                \
    ZMQ_LINKAGE ZMQ_EXPORT_BUF_SIZE_IMPL (__returntype__, __underlyingsize__)

#define ZMQ_EXPORT_STR_IMPL(__returntype__)                                    \
    _Must_inspect_result_ _Success_ (return != NULL)                           \
      _When_ (return != NULL, _Ret_z_) __returntype__
#define ZMQ_EXPORT_STR(__returntype__)                                         \
    ZMQ_LINKAGE ZMQ_EXPORT_STR_IMPL (__returntype__)

#define ZMQ_EXPORT_STR_SIZE_IMPL(__returntype__, __underlyingsize__)           \
    _Must_inspect_result_ _Success_ (return != NULL)                           \
      _Ret_writes_z_ (__underlyingsize__) __returntype__
#define ZMQ_EXPORT_STR_SIZE(__returntype__, __underlyingsize__)                \
    ZMQ_LINKAGE ZMQ_EXPORT_STR_SIZE_IMPL (__returntype__, __underlyingsize__)

/*  Define integer types needed for event interface                          */
#define ZMQ_DEFINED_STDINT 1
#if defined ZMQ_HAVE_SOLARIS || defined ZMQ_HAVE_OPENVMS
#include <inttypes.h>
#elif defined _MSC_VER && _MSC_VER < 1600
#ifndef uint64_t
typedef unsigned __int64 uint64_t;
#endif
#ifndef int32_t
typedef __int32 int32_t;
#endif
#ifndef uint32_t
typedef unsigned __int32 uint32_t;
#endif
#ifndef uint16_t
typedef unsigned __int16 uint16_t;
#endif
#ifndef uint8_t
typedef unsigned __int8 uint8_t;
#endif
#else
#include <stdint.h>
#endif

#if !defined _WIN32
// needed for sigset_t definition in zmq_ppoll
#include <signal.h>
#endif

//  32-bit AIX's pollfd struct members are called reqevents and rtnevents so it
//  defines compatibility macros for them. Need to include that header first to
//  stop build failures since zmq_pollset_t defines them as events and revents.
#ifdef ZMQ_HAVE_AIX
#include <poll.h>
#endif


/******************************************************************************/
/*  0MQ errors.                                                               */
/******************************************************************************/

/*  A number random enough not to collide with different errno ranges on      */
/*  different OSes. The assumption is that error_t is at least 32-bit type.   */
#define ZMQ_HAUSNUMERO 156384712

/*  On Windows platform some of the standard POSIX errnos are not defined.    */
#ifndef ENOTSUP
#define ENOTSUP (ZMQ_HAUSNUMERO + 1)
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT (ZMQ_HAUSNUMERO + 2)
#endif
#ifndef ENOBUFS
#define ENOBUFS (ZMQ_HAUSNUMERO + 3)
#endif
#ifndef ENETDOWN
#define ENETDOWN (ZMQ_HAUSNUMERO + 4)
#endif
#ifndef EADDRINUSE
#define EADDRINUSE (ZMQ_HAUSNUMERO + 5)
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL (ZMQ_HAUSNUMERO + 6)
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED (ZMQ_HAUSNUMERO + 7)
#endif
#ifndef EINPROGRESS
#define EINPROGRESS (ZMQ_HAUSNUMERO + 8)
#endif
#ifndef ENOTSOCK
#define ENOTSOCK (ZMQ_HAUSNUMERO + 9)
#endif
#ifndef EMSGSIZE
#define EMSGSIZE (ZMQ_HAUSNUMERO + 10)
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT (ZMQ_HAUSNUMERO + 11)
#endif
#ifndef ENETUNREACH
#define ENETUNREACH (ZMQ_HAUSNUMERO + 12)
#endif
#ifndef ECONNABORTED
#define ECONNABORTED (ZMQ_HAUSNUMERO + 13)
#endif
#ifndef ECONNRESET
#define ECONNRESET (ZMQ_HAUSNUMERO + 14)
#endif
#ifndef ENOTCONN
#define ENOTCONN (ZMQ_HAUSNUMERO + 15)
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT (ZMQ_HAUSNUMERO + 16)
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH (ZMQ_HAUSNUMERO + 17)
#endif
#ifndef ENETRESET
#define ENETRESET (ZMQ_HAUSNUMERO + 18)
#endif

/*  Native 0MQ error codes.                                                   */
#define EFSM (ZMQ_HAUSNUMERO + 51)
#define ENOCOMPATPROTO (ZMQ_HAUSNUMERO + 52)
#define ETERM (ZMQ_HAUSNUMERO + 53)
#define EMTHREAD (ZMQ_HAUSNUMERO + 54)

/*  This function retrieves the errno as it is known to 0MQ library. The goal */
/*  of this function is to make the code 100% portable, including where 0MQ   */
/*  compiled with certain CRT library (on Windows) is linked to an            */
/*  application that uses different CRT library.                              */
ZMQ_EXPORT (int) zmq_errno (void);

/*  Resolves system errors and 0MQ errors to human-readable string.           */
ZMQ_EXPORT_STR (const char *) zmq_strerror (int errnum_);

/*  Run-time API version detection                                            */
ZMQ_EXPORT_VOID
zmq_version (_Out_ int *major_, _Out_ int *minor_, _Out_ int *patch_);

/******************************************************************************/
/*  0MQ infrastructure (a.k.a. context) initialisation & termination.         */
/******************************************************************************/

/*  Context options                                                           */
#define ZMQ_IO_THREADS 1
#define ZMQ_MAX_SOCKETS 2
#define ZMQ_SOCKET_LIMIT 3
#define ZMQ_THREAD_PRIORITY 3
#define ZMQ_THREAD_SCHED_POLICY 4
#define ZMQ_MAX_MSGSZ 5
#define ZMQ_MSG_T_SIZE 6
#define ZMQ_THREAD_AFFINITY_CPU_ADD 7
#define ZMQ_THREAD_AFFINITY_CPU_REMOVE 8
#define ZMQ_THREAD_NAME_PREFIX 9

/*  Default for new contexts                                                  */
#define ZMQ_IO_THREADS_DFLT 1
#define ZMQ_MAX_SOCKETS_DFLT 1023
#define ZMQ_THREAD_PRIORITY_DFLT -1
#define ZMQ_THREAD_SCHED_POLICY_DFLT -1

ZMQ_EXPORT_PTR (void *, zmq::ctx_t) zmq_ctx_new (void);
ZMQ_EXPORT (int) zmq_ctx_term (_In_ _Post_invalid_ void *context_);
ZMQ_EXPORT (int) zmq_ctx_shutdown (_Inout_ void *context_);
ZMQ_EXPORT (int) zmq_ctx_set (_Inout_ void *context_, int option_, int optval_);
ZMQ_EXPORT (int) zmq_ctx_get (_In_ void *context_, int option_);

/*  Old (legacy) API                                                          */
ZMQ_EXPORT_PTR (void *, zmq::ctx_t)
zmq_init (_In_range_ (0, INT_MAX) int io_threads_);
ZMQ_EXPORT (int) zmq_term (_In_ _Post_invalid_ void *context_);
ZMQ_EXPORT (int) zmq_ctx_destroy (_In_ _Post_invalid_ void *context_);

/******************************************************************************/
/*  0MQ message definition.                                                   */
/******************************************************************************/

/* Some architectures, like sparc64 and some variants of aarch64, enforce pointer
 * alignment and raise sigbus on violations. Make sure applications allocate
 * zmq_msg_t on addresses aligned on a pointer-size boundary to avoid this issue.
 */
typedef struct zmq_msg_t
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
    __declspec(align (8)) unsigned char _[64];
#elif defined(_MSC_VER)                                                        \
  && (defined(_M_IX86) || defined(_M_ARM_ARMV7VE) || defined(_M_ARM))
    __declspec(align (4)) unsigned char _[64];
#elif defined(__GNUC__) || defined(__INTEL_COMPILER)                           \
  || (defined(__SUNPRO_C) && __SUNPRO_C >= 0x590)                              \
  || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
    unsigned char _[64] __attribute__ ((aligned (sizeof (void *))));
#else
    unsigned char _[64];
#endif
} zmq_msg_t;

typedef void (zmq_free_fn) (_Pre_maybenull_ _Post_invalid_ void *data_,
                            _In_opt_ void *hint_);

_At_ (msg_, _Pre_invalid_ _Pre_notnull_ _Post_valid_) ZMQ_EXPORT (int)
  zmq_msg_init (_Out_ zmq_msg_t *msg_);
_At_ (msg_, _Pre_invalid_ _Pre_notnull_ _Post_valid_) ZMQ_EXPORT (int)
  zmq_msg_init_size (_Out_ zmq_msg_t *msg_, size_t size_);
ZMQ_EXPORT (int)
_At_ (msg_, _Pre_invalid_ _Pre_notnull_ _Post_valid_)
  zmq_msg_init_data (_Out_ zmq_msg_t *msg_,
                     _In_reads_bytes_opt_ (size_) void *data_,
                     size_t size_,
                     _In_opt_ zmq_free_fn *ffn_,
                     _In_opt_ void *hint_);
ZMQ_EXPORT (int) zmq_msg_send (_In_ zmq_msg_t *msg_, _In_ void *s_, int flags_);
ZMQ_EXPORT (int)
zmq_msg_recv (_Out_ zmq_msg_t *msg_, _In_ void *s_, int flags_);
ZMQ_EXPORT (int) zmq_msg_close (_Inout_ zmq_msg_t *msg_);
ZMQ_EXPORT (int)
zmq_msg_move (_Inout_ zmq_msg_t *dest_, _Inout_ zmq_msg_t *src_);
ZMQ_EXPORT (int)
zmq_msg_copy (_Inout_ zmq_msg_t *dest_, _Inout_ zmq_msg_t *src_);
ZMQ_EXPORT_VOID_PTR zmq_msg_data (_In_ zmq_msg_t *msg_);
ZMQ_EXPORT (size_t) zmq_msg_size (_In_ const zmq_msg_t *msg_);
ZMQ_EXPORT (int) zmq_msg_more (_In_ const zmq_msg_t *msg_);
ZMQ_EXPORT (int) zmq_msg_get (_In_ const zmq_msg_t *msg_, int property_);
ZMQ_EXPORT (int)
zmq_msg_set (_Inout_ zmq_msg_t *msg_, int property_, int optval_);
ZMQ_EXPORT_STR (const char *)
zmq_msg_gets (_In_ const zmq_msg_t *msg_, _In_z_ const char *property_);

/******************************************************************************/
/*  0MQ socket definition.                                                    */
/******************************************************************************/

/*  Socket types.                                                             */
#define ZMQ_PAIR 0
#define ZMQ_PUB 1
#define ZMQ_SUB 2
#define ZMQ_REQ 3
#define ZMQ_REP 4
#define ZMQ_DEALER 5
#define ZMQ_ROUTER 6
#define ZMQ_PULL 7
#define ZMQ_PUSH 8
#define ZMQ_XPUB 9
#define ZMQ_XSUB 10
#define ZMQ_STREAM 11

/*  Deprecated aliases                                                        */
#define ZMQ_XREQ ZMQ_DEALER
#define ZMQ_XREP ZMQ_ROUTER

/*  Socket options.                                                           */
#define ZMQ_AFFINITY 4
#define ZMQ_ROUTING_ID 5
#define ZMQ_SUBSCRIBE 6
#define ZMQ_UNSUBSCRIBE 7
#define ZMQ_RATE 8
#define ZMQ_RECOVERY_IVL 9
#define ZMQ_SNDBUF 11
#define ZMQ_RCVBUF 12
#define ZMQ_RCVMORE 13
#define ZMQ_FD 14
#define ZMQ_EVENTS 15
#define ZMQ_TYPE 16
#define ZMQ_LINGER 17
#define ZMQ_RECONNECT_IVL 18
#define ZMQ_BACKLOG 19
#define ZMQ_RECONNECT_IVL_MAX 21
#define ZMQ_MAXMSGSIZE 22
#define ZMQ_SNDHWM 23
#define ZMQ_RCVHWM 24
#define ZMQ_MULTICAST_HOPS 25
#define ZMQ_RCVTIMEO 27
#define ZMQ_SNDTIMEO 28
#define ZMQ_LAST_ENDPOINT 32
#define ZMQ_ROUTER_MANDATORY 33
#define ZMQ_TCP_KEEPALIVE 34
#define ZMQ_TCP_KEEPALIVE_CNT 35
#define ZMQ_TCP_KEEPALIVE_IDLE 36
#define ZMQ_TCP_KEEPALIVE_INTVL 37
#define ZMQ_IMMEDIATE 39
#define ZMQ_XPUB_VERBOSE 40
#define ZMQ_ROUTER_RAW 41
#define ZMQ_IPV6 42
#define ZMQ_MECHANISM 43
#define ZMQ_PLAIN_SERVER 44
#define ZMQ_PLAIN_USERNAME 45
#define ZMQ_PLAIN_PASSWORD 46
#define ZMQ_CURVE_SERVER 47
#define ZMQ_CURVE_PUBLICKEY 48
#define ZMQ_CURVE_SECRETKEY 49
#define ZMQ_CURVE_SERVERKEY 50
#define ZMQ_PROBE_ROUTER 51
#define ZMQ_REQ_CORRELATE 52
#define ZMQ_REQ_RELAXED 53
#define ZMQ_CONFLATE 54
#define ZMQ_ZAP_DOMAIN 55
#define ZMQ_ROUTER_HANDOVER 56
#define ZMQ_TOS 57
#define ZMQ_CONNECT_ROUTING_ID 61
#define ZMQ_GSSAPI_SERVER 62
#define ZMQ_GSSAPI_PRINCIPAL 63
#define ZMQ_GSSAPI_SERVICE_PRINCIPAL 64
#define ZMQ_GSSAPI_PLAINTEXT 65
#define ZMQ_HANDSHAKE_IVL 66
#define ZMQ_SOCKS_PROXY 68
#define ZMQ_XPUB_NODROP 69
#define ZMQ_BLOCKY 70
#define ZMQ_XPUB_MANUAL 71
#define ZMQ_XPUB_WELCOME_MSG 72
#define ZMQ_STREAM_NOTIFY 73
#define ZMQ_INVERT_MATCHING 74
#define ZMQ_HEARTBEAT_IVL 75
#define ZMQ_HEARTBEAT_TTL 76
#define ZMQ_HEARTBEAT_TIMEOUT 77
#define ZMQ_XPUB_VERBOSER 78
#define ZMQ_CONNECT_TIMEOUT 79
#define ZMQ_TCP_MAXRT 80
#define ZMQ_THREAD_SAFE 81
#define ZMQ_MULTICAST_MAXTPDU 84
#define ZMQ_VMCI_BUFFER_SIZE 85
#define ZMQ_VMCI_BUFFER_MIN_SIZE 86
#define ZMQ_VMCI_BUFFER_MAX_SIZE 87
#define ZMQ_VMCI_CONNECT_TIMEOUT 88
#define ZMQ_USE_FD 89
#define ZMQ_GSSAPI_PRINCIPAL_NAMETYPE 90
#define ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE 91
#define ZMQ_BINDTODEVICE 92

/*  Message options                                                           */
#define ZMQ_MORE 1
#define ZMQ_SHARED 3

/*  Send/recv options.                                                        */
#define ZMQ_DONTWAIT 1
#define ZMQ_SNDMORE 2

/*  Security mechanisms                                                       */
#define ZMQ_NULL 0
#define ZMQ_PLAIN 1
#define ZMQ_CURVE 2
#define ZMQ_GSSAPI 3

/*  RADIO-DISH protocol                                                       */
#define ZMQ_GROUP_MAX_LENGTH 255

/*  Deprecated options and aliases                                            */
#define ZMQ_IDENTITY ZMQ_ROUTING_ID
#define ZMQ_CONNECT_RID ZMQ_CONNECT_ROUTING_ID
#define ZMQ_TCP_ACCEPT_FILTER 38
#define ZMQ_IPC_FILTER_PID 58
#define ZMQ_IPC_FILTER_UID 59
#define ZMQ_IPC_FILTER_GID 60
#define ZMQ_IPV4ONLY 31
#define ZMQ_DELAY_ATTACH_ON_CONNECT ZMQ_IMMEDIATE
#define ZMQ_NOBLOCK ZMQ_DONTWAIT
#define ZMQ_FAIL_UNROUTABLE ZMQ_ROUTER_MANDATORY
#define ZMQ_ROUTER_BEHAVIOR ZMQ_ROUTER_MANDATORY

/*  Deprecated Message options                                                */
#define ZMQ_SRCFD 2

/******************************************************************************/
/*  GSSAPI definitions                                                        */
/******************************************************************************/

/*  GSSAPI principal name types                                               */
#define ZMQ_GSSAPI_NT_HOSTBASED 0
#define ZMQ_GSSAPI_NT_USER_NAME 1
#define ZMQ_GSSAPI_NT_KRB5_PRINCIPAL 2

/******************************************************************************/
/*  0MQ socket events and monitoring                                          */
/******************************************************************************/

/*  Socket transport events (TCP, IPC and TIPC only)                          */

#define ZMQ_EVENT_CONNECTED 0x0001
#define ZMQ_EVENT_CONNECT_DELAYED 0x0002
#define ZMQ_EVENT_CONNECT_RETRIED 0x0004
#define ZMQ_EVENT_LISTENING 0x0008
#define ZMQ_EVENT_BIND_FAILED 0x0010
#define ZMQ_EVENT_ACCEPTED 0x0020
#define ZMQ_EVENT_ACCEPT_FAILED 0x0040
#define ZMQ_EVENT_CLOSED 0x0080
#define ZMQ_EVENT_CLOSE_FAILED 0x0100
#define ZMQ_EVENT_DISCONNECTED 0x0200
#define ZMQ_EVENT_MONITOR_STOPPED 0x0400
#define ZMQ_EVENT_ALL 0xFFFF
/*  Unspecified system errors during handshake. Event value is an errno.      */
#define ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL 0x0800
/*  Handshake complete successfully with successful authentication (if        *
 *  enabled). Event value is unused.                                          */
#define ZMQ_EVENT_HANDSHAKE_SUCCEEDED 0x1000
/*  Protocol errors between ZMTP peers or between server and ZAP handler.     *
 *  Event value is one of ZMQ_PROTOCOL_ERROR_*                                */
#define ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL 0x2000
/*  Failed authentication requests. Event value is the numeric ZAP status     *
 *  code, i.e. 300, 400 or 500.                                               */
#define ZMQ_EVENT_HANDSHAKE_FAILED_AUTH 0x4000
#define ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED 0x10000000
#define ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND 0x10000001
#define ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE 0x10000002
#define ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE 0x10000003
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED 0x10000011
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE 0x10000012
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO 0x10000013
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE 0x10000014
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR 0x10000015
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY 0x10000016
#define ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME 0x10000017
#define ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA 0x10000018
// the following two may be due to erroneous configuration of a peer
#define ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC 0x11000001
#define ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH 0x11000002
#define ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED 0x20000000
#define ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY 0x20000001
#define ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID 0x20000002
#define ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION 0x20000003
#define ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE 0x20000004
#define ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA 0x20000005
#define ZMQ_PROTOCOL_ERROR_WS_UNSPECIFIED 0x30000000

ZMQ_EXPORT_PTR (void *, zmq::socket_base_t)
zmq_socket (_In_ void *context_, int type_);
ZMQ_EXPORT (int) zmq_close (_In_ void *s_);
ZMQ_EXPORT (int)
zmq_setsockopt (_In_ void *s_,
                int option_,
                _In_reads_bytes_ (optvallen_) const void *optval_,
                size_t optvallen_);
ZMQ_EXPORT (int)
zmq_getsockopt (_In_ void *s_,
                int option_,
                _Out_writes_bytes_ (*optvallen_) void *optval_,
                _Inout_ size_t *optvallen_);
ZMQ_EXPORT (int) zmq_bind (_In_ void *s_, _In_z_ const char *addr_);
ZMQ_EXPORT (int) zmq_connect (_In_ void *s_, _In_z_ const char *addr_);
ZMQ_EXPORT (int) zmq_unbind (_In_ void *s_, _In_z_ const char *addr_);
ZMQ_EXPORT (int) zmq_disconnect (_In_ void *s_, _In_z_ const char *addr_);
ZMQ_EXPORT (int)
zmq_send (_In_ void *s_,
          _In_reads_bytes_ (len_) const void *buf_,
          size_t len_,
          int flags_);
ZMQ_EXPORT (int)
zmq_send_const (_In_ void *s_,
                _In_reads_bytes_ (len_) const void *buf_,
                size_t len_,
                int flags_);
ZMQ_EXPORT (int)
zmq_recv (_In_ void *s_,
          _Out_writes_bytes_ (len_) void *buf_,
          size_t len_,
          int flags_);
ZMQ_EXPORT (int)
zmq_socket_monitor (_In_ void *s_, _In_z_ const char *addr_, int events_);

/******************************************************************************/
/*  Hide socket fd type; this was before zmq_poller_event_t typedef below     */
/******************************************************************************/

#if defined _WIN32
// Windows uses a pointer-sized unsigned integer to store the socket fd.
#if defined _WIN64
typedef unsigned __int64 zmq_fd_t;
#else
typedef unsigned int zmq_fd_t;
#endif
#else
typedef int zmq_fd_t;
#endif

/******************************************************************************/
/*  Deprecated I/O multiplexing. Prefer using zmq_poller API                  */
/******************************************************************************/

#define ZMQ_POLLIN 1
#define ZMQ_POLLOUT 2
#define ZMQ_POLLERR 4
#define ZMQ_POLLPRI 8

typedef struct zmq_pollitem_t
{
    void *socket;
    zmq_fd_t fd;
    short events;
    short revents;
} zmq_pollitem_t;

#define ZMQ_POLLITEMS_DFLT 16

ZMQ_EXPORT (int)
zmq_poll (_In_reads_ (nitems_) zmq_pollitem_t *items_,
          int nitems_,
          long timeout_);

/******************************************************************************/
/*  Message proxying                                                          */
/******************************************************************************/

ZMQ_EXPORT (int)
zmq_proxy (_In_ void *frontend_, _In_ void *backend_, _In_opt_ void *capture_);
ZMQ_EXPORT (int)
zmq_proxy_steerable (_In_ void *frontend_,
                     _In_ void *backend_,
                     _In_opt_ void *capture_,
                     _In_opt_ void *control_);

/******************************************************************************/
/*  Probe library capabilities                                                */
/******************************************************************************/

#define ZMQ_HAS_CAPABILITIES 1
ZMQ_EXPORT (int) zmq_has (_In_z_ const char *capability_);

/*  Deprecated aliases */
#define ZMQ_STREAMER 1
#define ZMQ_FORWARDER 2
#define ZMQ_QUEUE 3

/*  Deprecated methods */
ZMQ_EXPORT (int)
zmq_device (int type_, _In_ void *frontend_, _In_ void *backend_);
ZMQ_EXPORT (int) zmq_sendmsg (_In_ void *s_, _In_ zmq_msg_t *msg_, int flags_);
ZMQ_EXPORT (int) zmq_recvmsg (_In_ void *s_, _Out_ zmq_msg_t *msg_, int flags_);
struct iovec;
ZMQ_EXPORT (int)
zmq_sendiov (_In_ void *s_,
             _In_reads_ (count_) struct iovec *iov_,
             size_t count_,
             int flags_);
ZMQ_EXPORT (int)
zmq_recviov (_In_ void *s_,
             _In_reads_ (*count_) struct iovec *iov_,
             _Inout_ size_t *count_,
             int flags_);

/******************************************************************************/
/*  Encryption functions                                                      */
/******************************************************************************/

/*  Encode data with Z85 encoding. Returns encoded data                       */
ZMQ_EXPORT_STR_SIZE (char *, size_ * 4 / 5 + 1)
zmq_z85_encode (_Out_writes_z_ (size_ * 4 / 5 + 1) char *dest_,
                _In_reads_bytes_ (size_) const uint8_t *data_,
                size_t size_);

/*  Decode data with Z85 encoding. Returns decoded data                       */
ZMQ_EXPORT_BUF_SIZE (uint8_t *, _String_length_ (string_) * 4 / 5)
zmq_z85_decode (_Out_writes_bytes_ (_String_length_ (string_) * 4 / 5)
                  uint8_t *dest_,
                _In_z_ const char *string_);

/*  Generate z85-encoded public and private keypair with libsodium. */
/*  Returns 0 on success.                                                     */
ZMQ_EXPORT (int)
zmq_curve_keypair (_Out_writes_z_ (41) char *z85_public_key_,
                   _Out_writes_z_ (41) char *z85_secret_key_);

/*  Derive the z85-encoded public key from the z85-encoded secret key.        */
/*  Returns 0 on success.                                                     */
ZMQ_EXPORT (int)
zmq_curve_public (_Out_writes_z_ (41) char *z85_public_key_,
                  _In_reads_z_ (41) const char *z85_secret_key_);

/******************************************************************************/
/*  Atomic utility methods                                                    */
/******************************************************************************/

ZMQ_EXPORT_PTR (void *, zmq::atomic_counter_t) zmq_atomic_counter_new (void);
ZMQ_EXPORT_VOID zmq_atomic_counter_set (_Inout_ void *counter_, int value_);
ZMQ_EXPORT (int) zmq_atomic_counter_inc (_Inout_ void *counter_);
ZMQ_EXPORT (int) zmq_atomic_counter_dec (_Inout_ void *counter_);
ZMQ_EXPORT (int) zmq_atomic_counter_value (_In_ void *counter_);
ZMQ_EXPORT_VOID
zmq_atomic_counter_destroy (_Inout_ _Deref_post_null_ void **counter_p_);

/******************************************************************************/
/*  Scheduling timers                                                         */
/******************************************************************************/

#define ZMQ_HAVE_TIMERS

typedef void (zmq_timer_fn) (int timer_id_, _In_opt_ void *arg_);

ZMQ_EXPORT_PTR (void *, zmq::timers_t) zmq_timers_new (void);
ZMQ_EXPORT (int)
zmq_timers_destroy (_Inout_ _Deref_post_null_ void **timers_p_);
ZMQ_EXPORT (int)
zmq_timers_add (_In_ void *timers_,
                size_t interval_,
                _In_ zmq_timer_fn handler_,
                _In_opt_ void *arg_);
ZMQ_EXPORT (int) zmq_timers_cancel (_In_ void *timers_, int timer_id_);
ZMQ_EXPORT (int)
zmq_timers_set_interval (_In_ void *timers_, int timer_id_, size_t interval_);
ZMQ_EXPORT (int) zmq_timers_reset (_In_ void *timers_, int timer_id_);
ZMQ_EXPORT (long) zmq_timers_timeout (_In_ void *timers_);
ZMQ_EXPORT (int) zmq_timers_execute (_In_ void *timers_);


/******************************************************************************/
/*  These functions are not documented by man pages -- use at your own risk.  */
/*  If you need these to be part of the formal ZMQ API, then (a) write a man  */
/*  page, and (b) write a test case in tests.                                 */
/******************************************************************************/

/*  Helper functions are used by perf tests so that they don't have to care   */
/*  about minutiae of time-related functions on different OS platforms.       */

/*  Starts the stopwatch. Returns the handle to the watch.                    */
ZMQ_EXPORT_PTR (void *, uint64_t) zmq_stopwatch_start (void);

/*  Returns the number of microseconds elapsed since the stopwatch was        */
/*  started, but does not stop or deallocate the stopwatch.                   */
ZMQ_EXPORT (unsigned long) zmq_stopwatch_intermediate (_In_ void *watch_);

/*  Stops the stopwatch. Returns the number of microseconds elapsed since     */
/*  the stopwatch was started, and deallocates that watch.                    */
ZMQ_EXPORT (unsigned long)
zmq_stopwatch_stop (_In_ _Post_invalid_ void *watch_);

/*  Sleeps for specified number of seconds.                                   */
ZMQ_EXPORT_VOID zmq_sleep (int seconds_);

typedef void (zmq_thread_fn) (_In_opt_ void *);

/* Start a thread. Returns a handle to the thread.                            */
ZMQ_EXPORT (void *)
zmq_threadstart (_In_ zmq_thread_fn *func_, _In_opt_ void *arg_);

/* Wait for thread to complete then free up resources.                        */
ZMQ_EXPORT_VOID zmq_threadclose (_In_ _Post_invalid_ void *thread_);


/******************************************************************************/
/*  These functions are DRAFT and disabled in stable releases, and subject to */
/*  change at ANY time until declared stable.                                 */
/******************************************************************************/

#ifdef ZMQ_BUILD_DRAFT_API

/*  DRAFT Socket types.                                                       */
#define ZMQ_SERVER 12
#define ZMQ_CLIENT 13
#define ZMQ_RADIO 14
#define ZMQ_DISH 15
#define ZMQ_GATHER 16
#define ZMQ_SCATTER 17
#define ZMQ_DGRAM 18
#define ZMQ_PEER 19
#define ZMQ_CHANNEL 20

/*  DRAFT Socket options.                                                     */
#define ZMQ_ZAP_ENFORCE_DOMAIN 93
#define ZMQ_LOOPBACK_FASTPATH 94
#define ZMQ_METADATA 95
#define ZMQ_MULTICAST_LOOP 96
#define ZMQ_ROUTER_NOTIFY 97
#define ZMQ_XPUB_MANUAL_LAST_VALUE 98
#define ZMQ_SOCKS_USERNAME 99
#define ZMQ_SOCKS_PASSWORD 100
#define ZMQ_IN_BATCH_SIZE 101
#define ZMQ_OUT_BATCH_SIZE 102
#define ZMQ_WSS_KEY_PEM 103
#define ZMQ_WSS_CERT_PEM 104
#define ZMQ_WSS_TRUST_PEM 105
#define ZMQ_WSS_HOSTNAME 106
#define ZMQ_WSS_TRUST_SYSTEM 107
#define ZMQ_ONLY_FIRST_SUBSCRIBE 108
#define ZMQ_RECONNECT_STOP 109
#define ZMQ_HELLO_MSG 110
#define ZMQ_DISCONNECT_MSG 111
#define ZMQ_PRIORITY 112
#define ZMQ_BUSY_POLL 113
#define ZMQ_HICCUP_MSG 114
#define ZMQ_XSUB_VERBOSE_UNSUBSCRIBE 115
#define ZMQ_TOPICS_COUNT 116
#define ZMQ_NORM_MODE 117
#define ZMQ_NORM_UNICAST_NACK 118
#define ZMQ_NORM_BUFFER_SIZE 119
#define ZMQ_NORM_SEGMENT_SIZE 120
#define ZMQ_NORM_BLOCK_SIZE 121
#define ZMQ_NORM_NUM_PARITY 122
#define ZMQ_NORM_NUM_AUTOPARITY 123
#define ZMQ_NORM_PUSH 124

/*  DRAFT ZMQ_NORM_MODE options                                               */
#define ZMQ_NORM_FIXED 0
#define ZMQ_NORM_CC 1
#define ZMQ_NORM_CCL 2
#define ZMQ_NORM_CCE 3
#define ZMQ_NORM_CCE_ECNONLY 4

/*  DRAFT ZMQ_RECONNECT_STOP options                                          */
#define ZMQ_RECONNECT_STOP_CONN_REFUSED 0x1
#define ZMQ_RECONNECT_STOP_HANDSHAKE_FAILED 0x2
#define ZMQ_RECONNECT_STOP_AFTER_DISCONNECT 0x4

/*  DRAFT Context options                                                     */
#define ZMQ_ZERO_COPY_RECV 10

/*  DRAFT Context methods.                                                    */
ZMQ_EXPORT (int)
zmq_ctx_set_ext (_In_ void *context_,
                 int option_,
                 _In_reads_bytes_ (optvallen_) const void *optval_,
                 size_t optvallen_);
ZMQ_EXPORT (int)
zmq_ctx_get_ext (_In_ void *context_,
                 int option_,
                 _Out_writes_bytes_ (*optvallen_) void *optval_,
                 size_t *optvallen_);

/*  DRAFT Socket methods.                                                     */
ZMQ_EXPORT (int) zmq_join (_In_ void *s_, _In_z_ const char *group_);
ZMQ_EXPORT (int) zmq_leave (_In_ void *s_, _In_z_ const char *group_);
ZMQ_EXPORT (uint32_t)
zmq_connect_peer (_In_ void *s_, _In_z_ const char *addr_);

/*  DRAFT Msg methods.                                                        */
ZMQ_EXPORT (int)
zmq_msg_set_routing_id (_Inout_ zmq_msg_t *msg_, uint32_t routing_id_);
ZMQ_EXPORT (uint32_t) zmq_msg_routing_id (_Inout_ zmq_msg_t *msg_);
ZMQ_EXPORT (int)
zmq_msg_set_group (_Inout_ zmq_msg_t *msg_, _In_z_ const char *group_);
ZMQ_EXPORT_STR (const char *) zmq_msg_group (_In_ zmq_msg_t *msg_);
_At_ (msg_, _Pre_invalid_ _Pre_notnull_ _Post_valid_) ZMQ_EXPORT (int)
  zmq_msg_init_buffer (_Out_ zmq_msg_t *msg_,
                       _In_reads_bytes_ (size_) const void *buf_,
                       size_t size_);

/*  DRAFT Msg property names.                                                 */
#define ZMQ_MSG_PROPERTY_ROUTING_ID "Routing-Id"
#define ZMQ_MSG_PROPERTY_SOCKET_TYPE "Socket-Type"
#define ZMQ_MSG_PROPERTY_USER_ID "User-Id"
#define ZMQ_MSG_PROPERTY_PEER_ADDRESS "Peer-Address"

/*  Router notify options                                                     */
#define ZMQ_NOTIFY_CONNECT 1
#define ZMQ_NOTIFY_DISCONNECT 2

/******************************************************************************/
/*  Poller polling on sockets,fd and thread-safe sockets                      */
/******************************************************************************/

#define ZMQ_HAVE_POLLER

typedef struct zmq_poller_event_t
{
    void *socket;
    zmq_fd_t fd;
    void *user_data;
    short events;
} zmq_poller_event_t;

ZMQ_EXPORT_PTR (void *, zmq::socket_poller_t) zmq_poller_new (void);
ZMQ_EXPORT (int)
zmq_poller_destroy (_Inout_ _Deref_post_null_ void **poller_p_);
ZMQ_EXPORT (int) zmq_poller_size (_In_ void *poller_);
ZMQ_EXPORT (int)
zmq_poller_add (_In_ void *poller_,
                _In_ void *socket_,
                _In_opt_ void *user_data_,
                short events_);
ZMQ_EXPORT (int)
zmq_poller_modify (_In_ void *poller_, _In_ void *socket_, short events_);
ZMQ_EXPORT (int) zmq_poller_remove (_In_ void *poller_, _In_ void *socket_);
ZMQ_EXPORT (int)
zmq_poller_wait (_In_ void *poller_,
                 _In_ zmq_poller_event_t *event_,
                 long timeout_);
ZMQ_EXPORT (int)
zmq_poller_wait_all (_In_ void *poller_,
                     _In_reads_ (n_events_) zmq_poller_event_t *events_,
                     int n_events_,
                     long timeout_);
ZMQ_EXPORT (int) zmq_poller_fd (_In_ void *poller_, _In_ zmq_fd_t *fd_);

ZMQ_EXPORT (int)
zmq_poller_add_fd (_In_ void *poller_,
                   zmq_fd_t fd_,
                   _In_ void *user_data_,
                   short events_);
ZMQ_EXPORT (int)
zmq_poller_modify_fd (_In_ void *poller_, zmq_fd_t fd_, short events_);
ZMQ_EXPORT (int) zmq_poller_remove_fd (_In_ void *poller_, zmq_fd_t fd_);

ZMQ_EXPORT (int)
zmq_socket_get_peer_state (_In_ void *socket_,
                           _In_reads_bytes_ (routing_id_size_)
                             const void *routing_id_,
                           size_t routing_id_size_);

/*  DRAFT Socket monitoring events                                            */
#define ZMQ_EVENT_PIPES_STATS 0x10000

#define ZMQ_CURRENT_EVENT_VERSION 1
#define ZMQ_CURRENT_EVENT_VERSION_DRAFT 2

#define ZMQ_EVENT_ALL_V1 ZMQ_EVENT_ALL
#define ZMQ_EVENT_ALL_V2 ZMQ_EVENT_ALL_V1 | ZMQ_EVENT_PIPES_STATS

ZMQ_EXPORT (int)
zmq_socket_monitor_versioned (_In_ void *s_,
                              _In_z_ const char *addr_,
                              uint64_t events_,
                              int event_version_,
                              int type_);
ZMQ_EXPORT (int) zmq_socket_monitor_pipes_stats (_In_ void *s);

#if !defined _WIN32
ZMQ_EXPORT (int)
zmq_ppoll (zmq_pollitem_t *items_,
           int nitems_,
           long timeout_,
           const sigset_t *sigmask_);
#else
// Windows has no sigset_t
ZMQ_EXPORT (int)
zmq_ppoll (_In_reads_ (nitems_) zmq_pollitem_t *items_,
           int nitems_,
           long timeout_,
           _In_ const void *sigmask_);
#endif

#endif // ZMQ_BUILD_DRAFT_API


#undef ZMQ_EXPORT

#ifdef __cplusplus
}
#endif

#endif
