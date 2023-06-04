/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_PLAIN_COMMON_HPP_INCLUDED__
#define __ZMQ_PLAIN_COMMON_HPP_INCLUDED__

namespace zmq
{
const char hello_prefix[] = "\x05HELLO";
const size_t hello_prefix_len = sizeof (hello_prefix) - 1;

const char welcome_prefix[] = "\x07WELCOME";
const size_t welcome_prefix_len = sizeof (welcome_prefix) - 1;

const char initiate_prefix[] = "\x08INITIATE";
const size_t initiate_prefix_len = sizeof (initiate_prefix) - 1;

const char ready_prefix[] = "\x05READY";
const size_t ready_prefix_len = sizeof (ready_prefix) - 1;

const char error_prefix[] = "\x05ERROR";
const size_t error_prefix_len = sizeof (error_prefix) - 1;

const size_t brief_len_size = sizeof (char);
}

#endif
