/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __TESTUTIL_MONITORING_HPP_INCLUDED__
#define __TESTUTIL_MONITORING_HPP_INCLUDED__

#include "../include/zmq.h"
#include "../src/stdint.hpp"

#include <stddef.h>

//  General, i.e. non-security specific, monitor utilities

int get_monitor_event_with_timeout (void *monitor_,
                                    int *value_,
                                    char **address_,
                                    int timeout_);

//  Read one event off the monitor socket; return value and address
//  by reference, if not null, and event number by value. Returns -1
//  in case of error.
int get_monitor_event (void *monitor_, int *value_, char **address_);

void expect_monitor_event (void *monitor_, int expected_event_);

void print_unexpected_event_stderr (int event_,
                                    int err_,
                                    int expected_event_,
                                    int expected_err_);

//  expects that one or more occurrences of the expected event are received
//  via the specified socket monitor
//  returns the number of occurrences of the expected event
//  interrupts, if a ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL with EPIPE, ECONNRESET
//  or ECONNABORTED occurs; in this case, 0 is returned
//  this should be investigated further, see
//  https://github.com/zeromq/libzmq/issues/2644
int expect_monitor_event_multiple (void *server_mon_,
                                   int expected_event_,
                                   int expected_err_ = -1,
                                   bool optional_ = false);

int64_t get_monitor_event_v2 (void *monitor_,
                              uint64_t **value_,
                              char **local_address_,
                              char **remote_address_);

void expect_monitor_event_v2 (void *monitor_,
                              int64_t expected_event_,
                              const char *expected_local_address_ = NULL,
                              const char *expected_remote_address_ = NULL);


const char *get_zmqEventName (uint64_t event);
void print_events (void *socket, int timeout, int limit);

#endif
