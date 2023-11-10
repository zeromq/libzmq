/* SPDX-License-Identifier: MPL-2.0 */

/*****************************************
* zmqp.h -- private header for libzmq.dll
*****************************************/

#ifndef __ZMQP_H_INCLUDED__
#define __ZMQP_H_INCLUDED__

ZMQ_FORCEINLINE void *zmqp_msg_data (_In_ zmq_msg_t *msg_);
ZMQ_FORCEINLINE size_t zmqp_msg_size (_In_ const zmq_msg_t *msg_);

#endif // __ZMQP_H_INCLUDED__
