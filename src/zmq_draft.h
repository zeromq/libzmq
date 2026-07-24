/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_DRAFT_H_INCLUDED__
#define __ZMQ_DRAFT_H_INCLUDED__

/******************************************************************************/
/*  These functions are DRAFT and disabled in stable releases, and subject to */
/*  change at ANY time until declared stable.                                 */
/******************************************************************************/

#ifndef ZMQ_BUILD_DRAFT_API

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
int zmq_ctx_set_ext (void *context_,
                     int option_,
                     const void *optval_,
                     size_t optvallen_);
int zmq_ctx_get_ext (void *context_,
                     int option_,
                     void *optval_,
                     size_t *optvallen_);

/*  DRAFT Socket methods.                                                     */
int zmq_join (void *s_, const char *group_);
int zmq_leave (void *s_, const char *group_);

/*  DRAFT Msg methods.                                                        */
int zmq_msg_set_routing_id (zmq_msg_t *msg_, uint32_t routing_id_);
uint32_t zmq_msg_routing_id (zmq_msg_t *msg_);
int zmq_msg_set_group (zmq_msg_t *msg_, const char *group_);
const char *zmq_msg_group (zmq_msg_t *msg_);
int zmq_msg_init_buffer (zmq_msg_t *msg_, const void *buf_, size_t size_);

/*  DRAFT Msg property names.                                                 */
#define ZMQ_MSG_PROPERTY_ROUTING_ID "Routing-Id"
#define ZMQ_MSG_PROPERTY_SOCKET_TYPE "Socket-Type"
#define ZMQ_MSG_PROPERTY_USER_ID "User-Id"
#define ZMQ_MSG_PROPERTY_PEER_ADDRESS "Peer-Address"

/*  Router notify options                                                     */
#define ZMQ_NOTIFY_CONNECT 1
#define ZMQ_NOTIFY_DISCONNECT 2

#endif // ZMQ_BUILD_DRAFT_API

#endif //ifndef __ZMQ_DRAFT_H_INCLUDED__
