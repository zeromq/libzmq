/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

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
    delay_attach_on_connect (0),
    delay_on_close (true),
    delay_on_disconnect (true),
    filter (false),
    recv_identity (false),
    raw_sock (false),
    tcp_keepalive (-1),
    tcp_keepalive_cnt (-1),
    tcp_keepalive_idle (-1),
    tcp_keepalive_intvl (-1),
    socket_id (0)
{
}

int zmq::options_t::setsockopt (int option_, const void *optval_,
    size_t optvallen_)
{
    bool valid = true;
    bool is_int = (optvallen_ == sizeof (int));
    int value = is_int? *((int *) optval_): 0;
    
    switch (option_) {
        case ZMQ_SNDHWM:
            if (is_int && value >= 0)
                sndhwm = value;
            else
                valid = false;
            break;
        
        case ZMQ_RCVHWM:
            if (is_int && value >= 0)
                rcvhwm = value;
            else
                valid = false;
            break;

        case ZMQ_AFFINITY:
            if (optvallen_ == sizeof (uint64_t))
                affinity = *((uint64_t*) optval_);
            else
                valid = false;
            break;

        case ZMQ_IDENTITY:
            //  Empty identity is invalid as well as identity longer than
            //  255 bytes. Identity starting with binary zero is invalid
            //  as these are used for auto-generated identities.
            if (optvallen_ > 0 && optvallen_ < 256
            && *((const unsigned char *) optval_) != 0) {
                identity_size = optvallen_;
                memcpy (identity, optval_, identity_size);
            }
            else
                valid = false;
            break;

        case ZMQ_RATE:
            if (is_int && value > 0)
                rate = value;
            else
                valid = false;
            break;

        case ZMQ_RECOVERY_IVL:
            if (is_int && value >= 0)
                recovery_ivl = value;
            else
                valid = false;

        case ZMQ_SNDBUF:
            if (is_int && value >= 0)
                sndbuf = value;
            else
                valid = false;
            break;

        case ZMQ_RCVBUF:
            if (is_int && value >= 0)
                rcvbuf = value;
            else
                valid = false;
            break;

        case ZMQ_LINGER:
            if (is_int && value >= -1)
                linger = value;
            else
                valid = false;
            break;

        case ZMQ_RECONNECT_IVL:
            if (is_int && value >= -1)
                reconnect_ivl = value;
            else
                valid = false;
            break;

        case ZMQ_RECONNECT_IVL_MAX:
            if (is_int && value >= 0)
                reconnect_ivl_max = value;
            else 
                valid = false;
            break;

        case ZMQ_BACKLOG:
            if (is_int && value >= 0)
                backlog = value;
            else
                valid = false;
            break;

        case ZMQ_MAXMSGSIZE:
            if (optvallen_ == sizeof (int64_t))
                maxmsgsize = *((int64_t *) optval_);
            else
                valid = false;
            break;

        case ZMQ_MULTICAST_HOPS:
            if (is_int && value > 0)
                multicast_hops = value;
            else
                valid = false;
            break;

        case ZMQ_RCVTIMEO:
            if (is_int && value >= -1)
                rcvtimeo = value;
            else
                valid = false;
            break;

        case ZMQ_SNDTIMEO:
            if (is_int && value >= -1)
                sndtimeo = value;
            else
                valid = false;
            break;

        /*  Deprecated in favor of ZMQ_IPV6  */
        case ZMQ_IPV4ONLY:
            if (is_int && (value == 0 || value == 1))
                ipv6 = 1 - value;
            else
                valid = false;
            break;

        /*  To replace the somewhat surprising IPV4ONLY */
        case ZMQ_IPV6:
            if (is_int && (value == 0 || value == 1))
                ipv6 = value;
            else
                valid = false;
            break;

        case ZMQ_TCP_KEEPALIVE:
            if (is_int && (value >= -1 || value <= 1))
                tcp_keepalive = value;
            else
                valid = false;
            break;

        case ZMQ_TCP_KEEPALIVE_CNT:
            if (is_int && (value == -1 || value >= 0))
                tcp_keepalive_cnt = value;
            else
                valid = false;
            break;

        case ZMQ_TCP_KEEPALIVE_IDLE:
            if (is_int && (value == -1 || value >= 0))
                tcp_keepalive_idle = value;
            else
                valid = false;
            break;

        case ZMQ_TCP_KEEPALIVE_INTVL:
            if (is_int && (value == -1 || value >= 0))
                tcp_keepalive_intvl = value;
            else
                valid = false;
            break;
            
        case ZMQ_DELAY_ATTACH_ON_CONNECT:
            if (is_int && (value == 0 || value == 1))
                delay_attach_on_connect = value;
            else
                valid = false;
            break;

        case ZMQ_TCP_ACCEPT_FILTER:
            if (optvallen_ == 0 && optval_ == NULL)
                tcp_accept_filters.clear ();
            else
            if (optvallen_ < 1 || optvallen_ > 255 || optval_ == NULL || *((const char*) optval_) == 0)
                valid = false;
            else {
                std::string filter_str ((const char *) optval_, optvallen_);
                tcp_address_mask_t mask;
                int rc = mask.resolve (filter_str.c_str (), ipv6);
                if (rc == 0)
                    tcp_accept_filters.push_back (mask);
                else
                    valid = false;
            }
            break;
            
        default:
            valid = false;
            break;
    }
    if (valid)
        return 0;
    else {
        errno = EINVAL;
        return -1;
    }
}

int zmq::options_t::getsockopt (int option_, void *optval_, size_t *optvallen_)
{
    switch (option_) {

    case ZMQ_SNDHWM:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = sndhwm;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RCVHWM:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = rcvhwm;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_AFFINITY:
        if (*optvallen_ < sizeof (uint64_t)) {
            errno = EINVAL;
            return -1;
        }
        *((uint64_t*) optval_) = affinity;
        *optvallen_ = sizeof (uint64_t);
        return 0;

    case ZMQ_IDENTITY:
        if (*optvallen_ < identity_size) {
            errno = EINVAL;
            return -1;
        }
        memcpy (optval_, identity, identity_size);
        *optvallen_ = identity_size;
        return 0;

    case ZMQ_RATE:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = rate;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RECOVERY_IVL:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = recovery_ivl;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_SNDBUF:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = sndbuf;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RCVBUF:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = rcvbuf;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_TYPE:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = type;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_LINGER:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = linger;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RECONNECT_IVL:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = reconnect_ivl;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RECONNECT_IVL_MAX:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = reconnect_ivl_max;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_BACKLOG:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = backlog;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_MAXMSGSIZE:
        if (*optvallen_ < sizeof (int64_t)) {
            errno = EINVAL;
            return -1;
        }
        *((int64_t*) optval_) = maxmsgsize;
        *optvallen_ = sizeof (int64_t);
        return 0;

    case ZMQ_MULTICAST_HOPS:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = multicast_hops;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_RCVTIMEO:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = rcvtimeo;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_SNDTIMEO:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = sndtimeo;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_IPV4ONLY:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = 1 - ipv6;
        *optvallen_ = sizeof (int);
        return 0;
        
    case ZMQ_IPV6:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = ipv6;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_DELAY_ATTACH_ON_CONNECT:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = delay_attach_on_connect;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_TCP_KEEPALIVE:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = tcp_keepalive;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_TCP_KEEPALIVE_CNT:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = tcp_keepalive_cnt;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_TCP_KEEPALIVE_IDLE:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = tcp_keepalive_idle;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_TCP_KEEPALIVE_INTVL:
        if (*optvallen_ < sizeof (int)) {
            errno = EINVAL;
            return -1;
        }
        *((int*) optval_) = tcp_keepalive_intvl;
        *optvallen_ = sizeof (int);
        return 0;

    case ZMQ_LAST_ENDPOINT:
        /*  don't allow string which cannot contain the entire message */
        if (*optvallen_ < last_endpoint.size() + 1) {
            errno = EINVAL;
            return -1;
        }
        memcpy (optval_, last_endpoint.c_str(), last_endpoint.size()+1);
        *optvallen_ = last_endpoint.size()+1;
        return 0;
    }

    errno = EINVAL;
    return -1;
}
