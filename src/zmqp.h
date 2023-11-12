/* SPDX-License-Identifier: MPL-2.0 */

/*****************************************
* zmqp.h -- private header for libzmq.dll
*****************************************/

#ifndef __ZMQP_H_INCLUDED__
#define __ZMQP_H_INCLUDED__

#ifndef LIBZMQ_FORCEINLINE
#ifdef _MSC_VER
#define LIBZMQ_FORCEINLINE __forceinline
#else
#define LIBZMQ_FORCEINLINE
#endif
#endif

LIBZMQ_FORCEINLINE void *zmqp_msg_data (_In_ zmq_msg_t *msg_);
LIBZMQ_FORCEINLINE size_t zmqp_msg_size (_In_ const zmq_msg_t *msg_);

#endif // __ZMQP_H_INCLUDED__
