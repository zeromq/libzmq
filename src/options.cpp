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

#include "options.hpp"
#include "err.hpp"
#include "../include/zmq_utils.h"

zmq::options_t::options_t () :
    sndhwm (1000),
    rcvhwm (1000),
    affinity (0),
    identity_size (0),
    rate (100),
    recovery_ivl (10000),
    multicast_hops (1),
    sndbuf (0),
    rcvbuf (0),
    type (-1),
    linger (-1),
    reconnect_ivl (100),
    reconnect_ivl_max (0),
    backlog (100),
    maxmsgsize (-1),
    rcvtimeo (-1),
    sndtimeo (-1),
    ipv6 (0),
    immediate (0),
    filter (false),
    recv_identity (false),
    raw_sock (false),
    tcp_keepalive (-1),
    tcp_keepalive_cnt (-1),
    tcp_keepalive_idle (-1),
    tcp_keepalive_intvl (-1),
    mechanism (ZMQ_NULL),
    as_server (0),
    socket_id (0),
    conflate (false)
{
}

int zmq::options_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    bool is_int = (optvallen_ == sizeof (int));
    int value = is_int? *((int *) optval_): 0;

    switch (option_) {
        case ZMQ_SNDHWM:
            if (is_int && value >= 0) {
                sndhwm = value;
                return 0;
            }
            break;

        case ZMQ_RCVHWM:
            if (is_int && value >= 0) {
                rcvhwm = value;
                return 0;
            }
            break;

        case ZMQ_AFFINITY:
            if (optvallen_ == sizeof (uint64_t)) {
                affinity = *((uint64_t*) optval_);
                return 0;
            }
            break;

        case ZMQ_IDENTITY:
            //  Empty identity is invalid as well as identity longer than
            //  255 bytes. Identity starting with binary zero is invalid
            //  as these are used for auto-generated identities.
            if (optvallen_ > 0 && optvallen_ < 256
            && *((const unsigned char *) optval_) != 0) {
                identity_size = optvallen_;
                memcpy (identity, optval_, identity_size);
                return 0;
            }
            break;

        case ZMQ_RATE:
            if (is_int && value > 0) {
                rate = value;
                return 0;
            }
            break;

        case ZMQ_RECOVERY_IVL:
            if (is_int && value >= 0) {
                recovery_ivl = value;
                return 0;
            }
            break;

        case ZMQ_SNDBUF:
            if (is_int && value >= 0) {
                sndbuf = value;
                return 0;
            }
            break;

        case ZMQ_RCVBUF:
            if (is_int && value >= 0) {
                rcvbuf = value;
                return 0;
            }
            break;

        case ZMQ_LINGER:
            if (is_int && value >= -1) {
                linger = value;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_IVL:
            if (is_int && value >= -1) {
                reconnect_ivl = value;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_IVL_MAX:
            if (is_int && value >= 0) {
                reconnect_ivl_max = value;
                return 0;
            }
            break;

        case ZMQ_BACKLOG:
            if (is_int && value >= 0) {
                backlog = value;
                return 0;
            }
            break;

        case ZMQ_MAXMSGSIZE:
            if (optvallen_ == sizeof (int64_t)) {
                maxmsgsize = *((int64_t *) optval_);
                return 0;
            }
            break;

        case ZMQ_MULTICAST_HOPS:
            if (is_int && value > 0) {
                multicast_hops = value;
                return 0;
            }
            break;

        case ZMQ_RCVTIMEO:
            if (is_int && value >= -1) {
                rcvtimeo = value;
                return 0;
            }
            break;

        case ZMQ_SNDTIMEO:
            if (is_int && value >= -1) {
                sndtimeo = value;
                return 0;
            }
            break;

        /*  Deprecated in favor of ZMQ_IPV6  */
        case ZMQ_IPV4ONLY:
            if (is_int && (value == 0 || value == 1)) {
                ipv6 = (value == 0);
                return 0;
            }
            break;

        /*  To replace the somewhat surprising IPV4ONLY */
        case ZMQ_IPV6:
            if (is_int && (value == 0 || value == 1)) {
                ipv6 = (value != 0);
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE:
            if (is_int && (value >= -1 || value <= 1)) {
                tcp_keepalive = value;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_CNT:
            if (is_int && (value == -1 || value >= 0)) {
                tcp_keepalive_cnt = value;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_IDLE:
            if (is_int && (value == -1 || value >= 0)) {
                tcp_keepalive_idle = value;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_INTVL:
            if (is_int && (value == -1 || value >= 0)) {
                tcp_keepalive_intvl = value;
                return 0;
            }
            break;

        case ZMQ_IMMEDIATE:
            if (is_int && (value == 0 || value == 1)) {
                immediate = value;
                return 0;
            }
            break;

        case ZMQ_TCP_ACCEPT_FILTER:
            if (optvallen_ == 0 && optval_ == NULL) {
                tcp_accept_filters.clear ();
                return 0;
            }
            else
            if (optvallen_ > 0 && optvallen_ < 256 && optval_ != NULL && *((const char*) optval_) != 0) {
                std::string filter_str ((const char *) optval_, optvallen_);
                tcp_address_mask_t mask;
                int rc = mask.resolve (filter_str.c_str (), ipv6);
                if (rc == 0) {
                    tcp_accept_filters.push_back (mask);
                    return 0;
                }
            }
            break;

        case ZMQ_PLAIN_SERVER:
            if (is_int && (value == 0 || value == 1)) {
                as_server = value;
                mechanism = value? ZMQ_PLAIN: ZMQ_NULL;
                return 0;
            }
            break;

        case ZMQ_PLAIN_USERNAME:
            if (optvallen_ == 0 && optval_ == NULL) {
                mechanism = ZMQ_NULL;
                return 0;
            }
            else
            if (optvallen_ > 0 && optvallen_ < 256 && optval_ != NULL) {
                plain_username.assign ((const char *) optval_, optvallen_);
                as_server = 0;
                mechanism = ZMQ_PLAIN;
                return 0;
            }
            break;

        case ZMQ_PLAIN_PASSWORD:
            if (optvallen_ == 0 && optval_ == NULL) {
                mechanism = ZMQ_NULL;
                return 0;
            }
            else
            if (optvallen_ > 0 && optvallen_ < 256 && optval_ != NULL) {
                plain_password.assign ((const char *) optval_, optvallen_);
                as_server = 0;
                mechanism = ZMQ_PLAIN;
                return 0;
            }
            break;

        case ZMQ_ZAP_DOMAIN:
            if (optvallen_ < 256) {
                zap_domain.assign ((const char *) optval_, optvallen_);
                return 0;
            }
            break;

        //  If libsodium isn't installed, these options provoke EINVAL
#       ifdef HAVE_LIBSODIUM
        case ZMQ_CURVE_SERVER:
            if (is_int && (value == 0 || value == 1)) {
                as_server = value;
                mechanism = value? ZMQ_CURVE: ZMQ_NULL;
                return 0;
            }
            break;

        case ZMQ_CURVE_PUBLICKEY:
            if (optvallen_ == CURVE_KEYSIZE) {
                memcpy (curve_public_key, optval_, CURVE_KEYSIZE);
                mechanism = ZMQ_CURVE;
                return 0;
            }
            else
            if (optvallen_ == CURVE_KEYSIZE_Z85) {
                zmq_z85_decode (curve_public_key, (char *) optval_);
                mechanism = ZMQ_CURVE;
                return 0;
            }
            break;

        case ZMQ_CURVE_SECRETKEY:
            if (optvallen_ == CURVE_KEYSIZE) {
                memcpy (curve_secret_key, optval_, CURVE_KEYSIZE);
                mechanism = ZMQ_CURVE;
                return 0;
            }
            else
            if (optvallen_ == CURVE_KEYSIZE_Z85) {
                zmq_z85_decode (curve_secret_key, (char *) optval_);
                mechanism = ZMQ_CURVE;
                return 0;
            }
            break;

        case ZMQ_CURVE_SERVERKEY:
            if (optvallen_ == CURVE_KEYSIZE) {
                memcpy (curve_server_key, optval_, CURVE_KEYSIZE);
                as_server = 0;
                mechanism = ZMQ_CURVE;
                return 0;
            }
            else
            if (optvallen_ == CURVE_KEYSIZE_Z85) {
                zmq_z85_decode (curve_server_key, (char *) optval_);
                as_server = 0;
                mechanism = ZMQ_CURVE;
                return 0;
            }
            break;
#       endif

        case ZMQ_CONFLATE:
            if (is_int && (value == 0 || value == 1)) {
                conflate = (value != 0);
                return 0;
            }
            break;

        default:
            break;
    }
    errno = EINVAL;
    return -1;
}

int zmq::options_t::getsockopt (int option_, void *optval_, size_t *optvallen_)
{
    bool is_int = (*optvallen_ == sizeof (int));
    int *value = (int *) optval_;

    switch (option_) {
        case ZMQ_SNDHWM:
            if (is_int) {
                *value = sndhwm;
                return 0;
            }
            break;

        case ZMQ_RCVHWM:
            if (is_int) {
                *value = rcvhwm;
                return 0;
            }
            break;

        case ZMQ_AFFINITY:
            if (*optvallen_ == sizeof (uint64_t)) {
                *((uint64_t *) optval_) = affinity;
                return 0;
            }
            break;

        case ZMQ_IDENTITY:
            if (*optvallen_ >= identity_size) {
                memcpy (optval_, identity, identity_size);
                *optvallen_ = identity_size;
                return 0;
            }
            break;

        case ZMQ_RATE:
            if (is_int) {
                *value = rate;
                return 0;
            }
            break;

        case ZMQ_RECOVERY_IVL:
            if (is_int) {
                *value = recovery_ivl;
                return 0;
            }
            break;

        case ZMQ_SNDBUF:
            if (is_int) {
                *value = sndbuf;
                return 0;
            }
            break;

        case ZMQ_RCVBUF:
            if (is_int) {
                *value = rcvbuf;
                return 0;
            }
            break;

        case ZMQ_TYPE:
            if (is_int) {
                *value = type;
                return 0;
            }
            break;

        case ZMQ_LINGER:
            if (is_int) {
                *value = linger;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_IVL:
            if (is_int) {
                *value = reconnect_ivl;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_IVL_MAX:
            if (is_int) {
                *value = reconnect_ivl_max;
                return 0;
            }
            break;

        case ZMQ_BACKLOG:
            if (is_int) {
                *value = backlog;
                return 0;
            }
            break;

        case ZMQ_MAXMSGSIZE:
            if (*optvallen_ == sizeof (int64_t)) {
                *((int64_t *) optval_) = maxmsgsize;
                *optvallen_ = sizeof (int64_t);
                return 0;
            }
            break;

        case ZMQ_MULTICAST_HOPS:
            if (is_int) {
                *value = multicast_hops;
                return 0;
            }
            break;

        case ZMQ_RCVTIMEO:
            if (is_int) {
                *value = rcvtimeo;
                return 0;
            }
            break;

        case ZMQ_SNDTIMEO:
            if (is_int) {
                *value = sndtimeo;
                return 0;
            }
            break;

        case ZMQ_IPV4ONLY:
            if (is_int) {
                *value = 1 - ipv6;
                return 0;
            }
            break;

        case ZMQ_IPV6:
            if (is_int) {
                *value = ipv6;
                return 0;
            }
            break;

        case ZMQ_IMMEDIATE:
            if (is_int) {
                *value = immediate;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE:
            if (is_int) {
                *value = tcp_keepalive;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_CNT:
            if (is_int) {
                *value = tcp_keepalive_cnt;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_IDLE:
            if (is_int) {
                *value = tcp_keepalive_idle;
                return 0;
            }
            break;

        case ZMQ_TCP_KEEPALIVE_INTVL:
            if (is_int) {
                *value = tcp_keepalive_intvl;
                return 0;
            }
            break;

        case ZMQ_MECHANISM:
            if (is_int) {
                *value = mechanism;
                return 0;
            }
            break;

        case ZMQ_PLAIN_SERVER:
            if (is_int) {
                *value = as_server && mechanism == ZMQ_PLAIN;
                return 0;
            }
            break;

        case ZMQ_PLAIN_USERNAME:
            if (*optvallen_ >= plain_username.size () + 1) {
                memcpy (optval_, plain_username.c_str (), plain_username.size () + 1);
                *optvallen_ = plain_username.size () + 1;
                return 0;
            }
            break;

        case ZMQ_PLAIN_PASSWORD:
            if (*optvallen_ >= plain_password.size () + 1) {
                memcpy (optval_, plain_password.c_str (), plain_password.size () + 1);
                *optvallen_ = plain_password.size () + 1;
                return 0;
            }
            break;

        case ZMQ_ZAP_DOMAIN:
            if (*optvallen_ >= zap_domain.size () + 1) {
                memcpy (optval_, zap_domain.c_str (), zap_domain.size () + 1);
                *optvallen_ = zap_domain.size () + 1;
                return 0;
            }
            break;

        //  If libsodium isn't installed, these options provoke EINVAL
#       ifdef HAVE_LIBSODIUM
        case ZMQ_CURVE_SERVER:
            if (is_int) {
                *value = as_server && mechanism == ZMQ_CURVE;
                return 0;
            }
            break;

        case ZMQ_CURVE_PUBLICKEY:
            if (*optvallen_ == CURVE_KEYSIZE) {
                memcpy (optval_, curve_public_key, CURVE_KEYSIZE);
                return 0;
            }
            else
            if (*optvallen_ == CURVE_KEYSIZE_Z85 + 1) {
                zmq_z85_encode ((char *) optval_, curve_public_key, CURVE_KEYSIZE);
                return 0;
            }
            break;

        case ZMQ_CURVE_SECRETKEY:
            if (*optvallen_ == CURVE_KEYSIZE) {
                memcpy (optval_, curve_secret_key, CURVE_KEYSIZE);
                return 0;
            }
            else
            if (*optvallen_ == CURVE_KEYSIZE_Z85 + 1) {
                zmq_z85_encode ((char *) optval_, curve_secret_key, CURVE_KEYSIZE);
                return 0;
            }
            break;

        case ZMQ_CURVE_SERVERKEY:
            if (*optvallen_ == CURVE_KEYSIZE) {
                memcpy (optval_, curve_server_key, CURVE_KEYSIZE);
                return 0;
            }
            else
            if (*optvallen_ == CURVE_KEYSIZE_Z85 + 1) {
                zmq_z85_encode ((char *) optval_, curve_server_key, CURVE_KEYSIZE);
                return 0;
            }
            break;
#       endif

        case ZMQ_CONFLATE:
            if (is_int) {
                *value = conflate;
                return 0;
            }
            break;

    }
    errno = EINVAL;
    return -1;
}
