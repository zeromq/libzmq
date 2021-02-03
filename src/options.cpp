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

#include "precompiled.hpp"
#include <string.h>
#include <limits.h>
#include <set>

#include "options.hpp"
#include "err.hpp"
#include "macros.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <net/if.h>
#endif

#if defined IFNAMSIZ
#define BINDDEVSIZ IFNAMSIZ
#else
#define BINDDEVSIZ 16
#endif

static int sockopt_invalid ()
{
#if defined(ZMQ_ACT_MILITANT)
    zmq_assert (false);
#endif
    errno = EINVAL;
    return -1;
}

int zmq::do_getsockopt (void *const optval_,
                        size_t *const optvallen_,
                        const std::string &value_)
{
    return do_getsockopt (optval_, optvallen_, value_.c_str (),
                          value_.size () + 1);
}

int zmq::do_getsockopt (void *const optval_,
                        size_t *const optvallen_,
                        const void *value_,
                        const size_t value_len_)
{
    // TODO behaviour is inconsistent with options_t::getsockopt; there, an
    // *exact* length match is required except for string-like (but not the
    // CURVE keys!) (and therefore null-ing remaining memory is a no-op, see
    // comment below)
    if (*optvallen_ < value_len_) {
        return sockopt_invalid ();
    }
    memcpy (optval_, value_, value_len_);
    // TODO why is the remaining memory null-ed?
    memset (static_cast<char *> (optval_) + value_len_, 0,
            *optvallen_ - value_len_);
    *optvallen_ = value_len_;
    return 0;
}

#ifdef ZMQ_HAVE_CURVE
static int do_getsockopt_curve_key (void *const optval_,
                                    const size_t *const optvallen_,
                                    const uint8_t (&curve_key_)[CURVE_KEYSIZE])
{
    if (*optvallen_ == CURVE_KEYSIZE) {
        memcpy (optval_, curve_key_, CURVE_KEYSIZE);
        return 0;
    }
    if (*optvallen_ == CURVE_KEYSIZE_Z85 + 1) {
        zmq_z85_encode (static_cast<char *> (optval_), curve_key_,
                        CURVE_KEYSIZE);
        return 0;
    }
    return sockopt_invalid ();
}
#endif

template <typename T>
static int do_setsockopt (const void *const optval_,
                          const size_t optvallen_,
                          T *const out_value_)
{
    if (optvallen_ == sizeof (T)) {
        memcpy (out_value_, optval_, sizeof (T));
        return 0;
    }
    return sockopt_invalid ();
}

int zmq::do_setsockopt_int_as_bool_strict (const void *const optval_,
                                           const size_t optvallen_,
                                           bool *const out_value_)
{
    // TODO handling of values other than 0 or 1 is not consistent,
    // here it is disallowed, but for other options such as
    // ZMQ_ROUTER_RAW any positive value is accepted
    int value = -1;
    if (do_setsockopt (optval_, optvallen_, &value) == -1)
        return -1;
    if (value == 0 || value == 1) {
        *out_value_ = (value != 0);
        return 0;
    }
    return sockopt_invalid ();
}

int zmq::do_setsockopt_int_as_bool_relaxed (const void *const optval_,
                                            const size_t optvallen_,
                                            bool *const out_value_)
{
    int value = -1;
    if (do_setsockopt (optval_, optvallen_, &value) == -1)
        return -1;
    *out_value_ = (value != 0);
    return 0;
}

static int
do_setsockopt_string_allow_empty_strict (const void *const optval_,
                                         const size_t optvallen_,
                                         std::string *const out_value_,
                                         const size_t max_len_)
{
    // TODO why is optval_ != NULL not allowed in case of optvallen_== 0?
    // TODO why are empty strings allowed for some socket options, but not for others?
    if (optval_ == NULL && optvallen_ == 0) {
        out_value_->clear ();
        return 0;
    }
    if (optval_ != NULL && optvallen_ > 0 && optvallen_ <= max_len_) {
        out_value_->assign (static_cast<const char *> (optval_), optvallen_);
        return 0;
    }
    return sockopt_invalid ();
}

static int
do_setsockopt_string_allow_empty_relaxed (const void *const optval_,
                                          const size_t optvallen_,
                                          std::string *const out_value_,
                                          const size_t max_len_)
{
    // TODO use either do_setsockopt_string_allow_empty_relaxed or
    // do_setsockopt_string_allow_empty_strict everywhere
    if (optvallen_ > 0 && optvallen_ <= max_len_) {
        out_value_->assign (static_cast<const char *> (optval_), optvallen_);
        return 0;
    }
    return sockopt_invalid ();
}

template <typename T>
static int do_setsockopt_set (const void *const optval_,
                              const size_t optvallen_,
                              std::set<T> *const set_)
{
    if (optvallen_ == 0 && optval_ == NULL) {
        set_->clear ();
        return 0;
    }
    if (optvallen_ == sizeof (T) && optval_ != NULL) {
        set_->insert (*(static_cast<const T *> (optval_)));
        return 0;
    }
    return sockopt_invalid ();
}

// TODO why is 1000 a sensible default?
const int default_hwm = 1000;

zmq::options_t::options_t () :
    sndhwm (default_hwm),
    rcvhwm (default_hwm),
    affinity (0),
    routing_id_size (0),
    rate (100),
    recovery_ivl (10000),
    multicast_hops (1),
    multicast_maxtpdu (1500),
    sndbuf (-1),
    rcvbuf (-1),
    tos (0),
    priority (0),
    type (-1),
    linger (-1),
    connect_timeout (0),
    tcp_maxrt (0),
    reconnect_stop (0),
    reconnect_ivl (100),
    reconnect_ivl_max (0),
    backlog (100),
    maxmsgsize (-1),
    rcvtimeo (-1),
    sndtimeo (-1),
    ipv6 (false),
    immediate (0),
    filter (false),
    invert_matching (false),
    recv_routing_id (false),
    raw_socket (false),
    raw_notify (true),
    tcp_keepalive (-1),
    tcp_keepalive_cnt (-1),
    tcp_keepalive_idle (-1),
    tcp_keepalive_intvl (-1),
    mechanism (ZMQ_NULL),
    as_server (0),
    gss_principal_nt (ZMQ_GSSAPI_NT_HOSTBASED),
    gss_service_principal_nt (ZMQ_GSSAPI_NT_HOSTBASED),
    gss_plaintext (false),
    socket_id (0),
    conflate (false),
    handshake_ivl (30000),
    connected (false),
    heartbeat_ttl (0),
    heartbeat_interval (0),
    heartbeat_timeout (-1),
    use_fd (-1),
    zap_enforce_domain (false),
    loopback_fastpath (false),
    multicast_loop (true),
    in_batch_size (8192),
    out_batch_size (8192),
    zero_copy (true),
    router_notify (0),
    monitor_event_version (1),
    wss_trust_system (false),
    hello_msg (),
    can_send_hello_msg (false),
    disconnect_msg (),
    can_recv_disconnect_msg (false)
{
    memset (curve_public_key, 0, CURVE_KEYSIZE);
    memset (curve_secret_key, 0, CURVE_KEYSIZE);
    memset (curve_server_key, 0, CURVE_KEYSIZE);
#if defined ZMQ_HAVE_VMCI
    vmci_buffer_size = 0;
    vmci_buffer_min_size = 0;
    vmci_buffer_max_size = 0;
    vmci_connect_timeout = -1;
#endif
}

int zmq::options_t::set_curve_key (uint8_t *destination_,
                                   const void *optval_,
                                   size_t optvallen_)
{
    switch (optvallen_) {
        case CURVE_KEYSIZE:
            memcpy (destination_, optval_, optvallen_);
            mechanism = ZMQ_CURVE;
            return 0;

        case CURVE_KEYSIZE_Z85 + 1: {
            const std::string s (static_cast<const char *> (optval_),
                                 optvallen_);

            if (zmq_z85_decode (destination_, s.c_str ())) {
                mechanism = ZMQ_CURVE;
                return 0;
            }
            break;
        }

        case CURVE_KEYSIZE_Z85:
            char z85_key[CURVE_KEYSIZE_Z85 + 1];
            memcpy (z85_key, reinterpret_cast<const char *> (optval_),
                    optvallen_);
            z85_key[CURVE_KEYSIZE_Z85] = 0;
            if (zmq_z85_decode (destination_, z85_key)) {
                mechanism = ZMQ_CURVE;
                return 0;
            }
            break;

        default:
            break;
    }
    return -1;
}

const int deciseconds_per_millisecond = 100;

int zmq::options_t::setsockopt (int option_,
                                const void *optval_,
                                size_t optvallen_)
{
    const bool is_int = (optvallen_ == sizeof (int));
    int value = 0;
    if (is_int)
        memcpy (&value, optval_, sizeof (int));
#if defined(ZMQ_ACT_MILITANT)
    bool malformed = true; //  Did caller pass a bad option value?
#endif

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
            return do_setsockopt (optval_, optvallen_, &affinity);

        case ZMQ_ROUTING_ID:
            //  Routing id is any binary string from 1 to 255 octets
            if (optvallen_ > 0 && optvallen_ <= UCHAR_MAX) {
                routing_id_size = static_cast<unsigned char> (optvallen_);
                memcpy (routing_id, optval_, routing_id_size);
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
            if (is_int && value >= -1) {
                sndbuf = value;
                return 0;
            }
            break;

        case ZMQ_RCVBUF:
            if (is_int && value >= -1) {
                rcvbuf = value;
                return 0;
            }
            break;

        case ZMQ_TOS:
            if (is_int && value >= 0) {
                tos = value;
                return 0;
            }
            break;

        case ZMQ_LINGER:
            if (is_int && value >= -1) {
                linger.store (value);
                return 0;
            }
            break;

        case ZMQ_CONNECT_TIMEOUT:
            if (is_int && value >= 0) {
                connect_timeout = value;
                return 0;
            }
            break;

        case ZMQ_TCP_MAXRT:
            if (is_int && value >= 0) {
                tcp_maxrt = value;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_STOP:
            if (is_int) {
                reconnect_stop = value;
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
            return do_setsockopt (optval_, optvallen_, &maxmsgsize);

        case ZMQ_MULTICAST_HOPS:
            if (is_int && value > 0) {
                multicast_hops = value;
                return 0;
            }
            break;

        case ZMQ_MULTICAST_MAXTPDU:
            if (is_int && value > 0) {
                multicast_maxtpdu = value;
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
        case ZMQ_IPV4ONLY: {
            bool value;
            const int rc =
              do_setsockopt_int_as_bool_strict (optval_, optvallen_, &value);
            if (rc == 0)
                ipv6 = !value;
            return rc;
        }

        /*  To replace the somewhat surprising IPV4ONLY */
        case ZMQ_IPV6:
            return do_setsockopt_int_as_bool_strict (optval_, optvallen_,
                                                     &ipv6);

        case ZMQ_SOCKS_PROXY:
            return do_setsockopt_string_allow_empty_strict (
              optval_, optvallen_, &socks_proxy_address, SIZE_MAX);

        case ZMQ_SOCKS_USERNAME:
            /* Make empty string or NULL equivalent. */
            if (optval_ == NULL || optvallen_ == 0) {
                socks_proxy_username.clear ();
                return 0;
            } else {
                return do_setsockopt_string_allow_empty_strict (
                  optval_, optvallen_, &socks_proxy_username, 255);
            }
        case ZMQ_SOCKS_PASSWORD:
            /* Make empty string or NULL equivalent. */
            if (optval_ == NULL || optvallen_ == 0) {
                socks_proxy_password.clear ();
                return 0;
            } else {
                return do_setsockopt_string_allow_empty_strict (
                  optval_, optvallen_, &socks_proxy_password, 255);
            }
        case ZMQ_TCP_KEEPALIVE:
            if (is_int && (value == -1 || value == 0 || value == 1)) {
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
            // TODO why is immediate not bool (and called non_immediate, as its meaning appears to be reversed)
            if (is_int && (value == 0 || value == 1)) {
                immediate = value;
                return 0;
            }
            break;

        case ZMQ_TCP_ACCEPT_FILTER: {
            std::string filter_str;
            int rc = do_setsockopt_string_allow_empty_strict (
              optval_, optvallen_, &filter_str, UCHAR_MAX);
            if (rc == 0) {
                if (filter_str.empty ()) {
                    tcp_accept_filters.clear ();
                } else {
                    tcp_address_mask_t mask;
                    rc = mask.resolve (filter_str.c_str (), ipv6);
                    if (rc == 0) {
                        tcp_accept_filters.push_back (mask);
                    }
                }
            }
            return rc;
        }

#if defined ZMQ_HAVE_SO_PEERCRED || defined ZMQ_HAVE_LOCAL_PEERCRED
        case ZMQ_IPC_FILTER_UID:
            return do_setsockopt_set (optval_, optvallen_,
                                      &ipc_uid_accept_filters);


        case ZMQ_IPC_FILTER_GID:
            return do_setsockopt_set (optval_, optvallen_,
                                      &ipc_gid_accept_filters);
#endif

#if defined ZMQ_HAVE_SO_PEERCRED
        case ZMQ_IPC_FILTER_PID:
            return do_setsockopt_set (optval_, optvallen_,
                                      &ipc_pid_accept_filters);
#endif

        case ZMQ_PLAIN_SERVER:
            if (is_int && (value == 0 || value == 1)) {
                as_server = value;
                mechanism = value ? ZMQ_PLAIN : ZMQ_NULL;
                return 0;
            }
            break;

        case ZMQ_PLAIN_USERNAME:
            if (optvallen_ == 0 && optval_ == NULL) {
                mechanism = ZMQ_NULL;
                return 0;
            } else if (optvallen_ > 0 && optvallen_ <= UCHAR_MAX
                       && optval_ != NULL) {
                plain_username.assign (static_cast<const char *> (optval_),
                                       optvallen_);
                as_server = 0;
                mechanism = ZMQ_PLAIN;
                return 0;
            }
            break;

        case ZMQ_PLAIN_PASSWORD:
            if (optvallen_ == 0 && optval_ == NULL) {
                mechanism = ZMQ_NULL;
                return 0;
            } else if (optvallen_ > 0 && optvallen_ <= UCHAR_MAX
                       && optval_ != NULL) {
                plain_password.assign (static_cast<const char *> (optval_),
                                       optvallen_);
                as_server = 0;
                mechanism = ZMQ_PLAIN;
                return 0;
            }
            break;

        case ZMQ_ZAP_DOMAIN:
            return do_setsockopt_string_allow_empty_relaxed (
              optval_, optvallen_, &zap_domain, UCHAR_MAX);

            //  If curve encryption isn't built, these options provoke EINVAL
#ifdef ZMQ_HAVE_CURVE
        case ZMQ_CURVE_SERVER:
            if (is_int && (value == 0 || value == 1)) {
                as_server = value;
                mechanism = value ? ZMQ_CURVE : ZMQ_NULL;
                return 0;
            }
            break;

        case ZMQ_CURVE_PUBLICKEY:
            if (0 == set_curve_key (curve_public_key, optval_, optvallen_)) {
                return 0;
            }
            break;

        case ZMQ_CURVE_SECRETKEY:
            if (0 == set_curve_key (curve_secret_key, optval_, optvallen_)) {
                return 0;
            }
            break;

        case ZMQ_CURVE_SERVERKEY:
            if (0 == set_curve_key (curve_server_key, optval_, optvallen_)) {
                as_server = 0;
                return 0;
            }
            break;
#endif

        case ZMQ_CONFLATE:
            return do_setsockopt_int_as_bool_strict (optval_, optvallen_,
                                                     &conflate);

            //  If libgssapi isn't installed, these options provoke EINVAL
#ifdef HAVE_LIBGSSAPI_KRB5
        case ZMQ_GSSAPI_SERVER:
            if (is_int && (value == 0 || value == 1)) {
                as_server = value;
                mechanism = ZMQ_GSSAPI;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_PRINCIPAL:
            if (optvallen_ > 0 && optvallen_ <= UCHAR_MAX && optval_ != NULL) {
                gss_principal.assign ((const char *) optval_, optvallen_);
                mechanism = ZMQ_GSSAPI;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
            if (optvallen_ > 0 && optvallen_ <= UCHAR_MAX && optval_ != NULL) {
                gss_service_principal.assign ((const char *) optval_,
                                              optvallen_);
                mechanism = ZMQ_GSSAPI;
                as_server = 0;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_PLAINTEXT:
            return do_setsockopt_int_as_bool_strict (optval_, optvallen_,
                                                     &gss_plaintext);

        case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
            if (is_int
                && (value == ZMQ_GSSAPI_NT_HOSTBASED
                    || value == ZMQ_GSSAPI_NT_USER_NAME
                    || value == ZMQ_GSSAPI_NT_KRB5_PRINCIPAL)) {
                gss_principal_nt = value;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
            if (is_int
                && (value == ZMQ_GSSAPI_NT_HOSTBASED
                    || value == ZMQ_GSSAPI_NT_USER_NAME
                    || value == ZMQ_GSSAPI_NT_KRB5_PRINCIPAL)) {
                gss_service_principal_nt = value;
                return 0;
            }
            break;
#endif

        case ZMQ_HANDSHAKE_IVL:
            if (is_int && value >= 0) {
                handshake_ivl = value;
                return 0;
            }
            break;

        case ZMQ_INVERT_MATCHING:
            return do_setsockopt_int_as_bool_relaxed (optval_, optvallen_,
                                                      &invert_matching);

        case ZMQ_HEARTBEAT_IVL:
            if (is_int && value >= 0) {
                heartbeat_interval = value;
                return 0;
            }
            break;

        case ZMQ_HEARTBEAT_TTL:
            // Convert this to deciseconds from milliseconds
            value = value / deciseconds_per_millisecond;
            if (is_int && value >= 0 && value <= UINT16_MAX) {
                heartbeat_ttl = static_cast<uint16_t> (value);
                return 0;
            }
            break;

        case ZMQ_HEARTBEAT_TIMEOUT:
            if (is_int && value >= 0) {
                heartbeat_timeout = value;
                return 0;
            }
            break;

#ifdef ZMQ_HAVE_VMCI
        case ZMQ_VMCI_BUFFER_SIZE:
            return do_setsockopt (optval_, optvallen_, &vmci_buffer_size);

        case ZMQ_VMCI_BUFFER_MIN_SIZE:
            return do_setsockopt (optval_, optvallen_, &vmci_buffer_min_size);

        case ZMQ_VMCI_BUFFER_MAX_SIZE:
            return do_setsockopt (optval_, optvallen_, &vmci_buffer_max_size);

        case ZMQ_VMCI_CONNECT_TIMEOUT:
            return do_setsockopt (optval_, optvallen_, &vmci_connect_timeout);
#endif

        case ZMQ_USE_FD:
            if (is_int && value >= -1) {
                use_fd = value;
                return 0;
            }
            break;

        case ZMQ_BINDTODEVICE:
            return do_setsockopt_string_allow_empty_strict (
              optval_, optvallen_, &bound_device, BINDDEVSIZ);

        case ZMQ_ZAP_ENFORCE_DOMAIN:
            return do_setsockopt_int_as_bool_relaxed (optval_, optvallen_,
                                                      &zap_enforce_domain);

        case ZMQ_LOOPBACK_FASTPATH:
            return do_setsockopt_int_as_bool_relaxed (optval_, optvallen_,
                                                      &loopback_fastpath);

        case ZMQ_METADATA:
            if (optvallen_ > 0 && !is_int) {
                const std::string s (static_cast<const char *> (optval_),
                                     optvallen_);
                const size_t pos = s.find (':');
                if (pos != std::string::npos && pos != 0
                    && pos != s.length () - 1) {
                    const std::string key = s.substr (0, pos);
                    if (key.compare (0, 2, "X-") == 0
                        && key.length () <= UCHAR_MAX) {
                        std::string val = s.substr (pos + 1, s.length ());
                        app_metadata.insert (
                          std::pair<std::string, std::string> (key, val));
                        return 0;
                    }
                }
            }
            errno = EINVAL;
            return -1;

        case ZMQ_MULTICAST_LOOP:
            return do_setsockopt_int_as_bool_relaxed (optval_, optvallen_,
                                                      &multicast_loop);

#ifdef ZMQ_BUILD_DRAFT_API
        case ZMQ_IN_BATCH_SIZE:
            if (is_int && value > 0) {
                in_batch_size = value;
                return 0;
            }
            break;

        case ZMQ_OUT_BATCH_SIZE:
            if (is_int && value > 0) {
                out_batch_size = value;
                return 0;
            }
            break;

#ifdef ZMQ_HAVE_WSS
        case ZMQ_WSS_KEY_PEM:
            // TODO: check if valid certificate
            wss_key_pem = std::string ((char *) optval_, optvallen_);
            return 0;
        case ZMQ_WSS_CERT_PEM:
            // TODO: check if valid certificate
            wss_cert_pem = std::string ((char *) optval_, optvallen_);
            return 0;
        case ZMQ_WSS_TRUST_PEM:
            // TODO: check if valid certificate
            wss_trust_pem = std::string ((char *) optval_, optvallen_);
            return 0;
        case ZMQ_WSS_HOSTNAME:
            wss_hostname = std::string ((char *) optval_, optvallen_);
            return 0;
        case ZMQ_WSS_TRUST_SYSTEM:
            return do_setsockopt_int_as_bool_strict (optval_, optvallen_,
                                                     &wss_trust_system);
#endif

        case ZMQ_HELLO_MSG:
            if (optvallen_ > 0) {
                unsigned char *bytes = (unsigned char *) optval_;
                hello_msg =
                  std::vector<unsigned char> (bytes, bytes + optvallen_);
            } else {
                hello_msg = std::vector<unsigned char> ();
            }

            return 0;

        case ZMQ_DISCONNECT_MSG:
            if (optvallen_ > 0) {
                unsigned char *bytes = (unsigned char *) optval_;
                disconnect_msg =
                  std::vector<unsigned char> (bytes, bytes + optvallen_);
            } else {
                disconnect_msg = std::vector<unsigned char> ();
            }

            return 0;

        case ZMQ_PRIORITY:
            if (is_int && value >= 0) {
                priority = value;
                return 0;
            }
            break;

#endif

        default:
#if defined(ZMQ_ACT_MILITANT)
            //  There are valid scenarios for probing with unknown socket option
            //  values, e.g. to check if security is enabled or not. This will not
            //  provoke a militant assert. However, passing bad values to a valid
            //  socket option will, if ZMQ_ACT_MILITANT is defined.
            malformed = false;
#endif
            break;
    }

        // TODO mechanism should either be set explicitly, or determined when
        // connecting. currently, it depends on the order of setsockopt calls
        // if there is some inconsistency, which is confusing. in addition,
        // the assumed or set mechanism should be queryable (as a socket option)

#if defined(ZMQ_ACT_MILITANT)
    //  There is no valid use case for passing an error back to the application
    //  when it sent malformed arguments to a socket option. Use ./configure
    //  --with-militant to enable this checking.
    if (malformed)
        zmq_assert (false);
#endif
    errno = EINVAL;
    return -1;
}

int zmq::options_t::getsockopt (int option_,
                                void *optval_,
                                size_t *optvallen_) const
{
    const bool is_int = (*optvallen_ == sizeof (int));
    int *value = static_cast<int *> (optval_);
#if defined(ZMQ_ACT_MILITANT)
    bool malformed = true; //  Did caller pass a bad option value?
#endif

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
                *(static_cast<uint64_t *> (optval_)) = affinity;
                return 0;
            }
            break;

        case ZMQ_ROUTING_ID:
            return do_getsockopt (optval_, optvallen_, routing_id,
                                  routing_id_size);

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

        case ZMQ_TOS:
            if (is_int) {
                *value = tos;
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
                *value = linger.load ();
                return 0;
            }
            break;

        case ZMQ_CONNECT_TIMEOUT:
            if (is_int) {
                *value = connect_timeout;
                return 0;
            }
            break;

        case ZMQ_TCP_MAXRT:
            if (is_int) {
                *value = tcp_maxrt;
                return 0;
            }
            break;

        case ZMQ_RECONNECT_STOP:
            if (is_int) {
                *value = reconnect_stop;
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
                *(static_cast<int64_t *> (optval_)) = maxmsgsize;
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

        case ZMQ_MULTICAST_MAXTPDU:
            if (is_int) {
                *value = multicast_maxtpdu;
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

        case ZMQ_SOCKS_PROXY:
            return do_getsockopt (optval_, optvallen_, socks_proxy_address);

        case ZMQ_SOCKS_USERNAME:
            return do_getsockopt (optval_, optvallen_, socks_proxy_username);

        case ZMQ_SOCKS_PASSWORD:
            return do_getsockopt (optval_, optvallen_, socks_proxy_password);

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
            return do_getsockopt (optval_, optvallen_, plain_username);

        case ZMQ_PLAIN_PASSWORD:
            return do_getsockopt (optval_, optvallen_, plain_password);

        case ZMQ_ZAP_DOMAIN:
            return do_getsockopt (optval_, optvallen_, zap_domain);

            //  If curve encryption isn't built, these options provoke EINVAL
#ifdef ZMQ_HAVE_CURVE
        case ZMQ_CURVE_SERVER:
            if (is_int) {
                *value = as_server && mechanism == ZMQ_CURVE;
                return 0;
            }
            break;

        case ZMQ_CURVE_PUBLICKEY:
            return do_getsockopt_curve_key (optval_, optvallen_,
                                            curve_public_key);

        case ZMQ_CURVE_SECRETKEY:
            return do_getsockopt_curve_key (optval_, optvallen_,
                                            curve_secret_key);

        case ZMQ_CURVE_SERVERKEY:
            return do_getsockopt_curve_key (optval_, optvallen_,
                                            curve_server_key);
#endif

        case ZMQ_CONFLATE:
            if (is_int) {
                *value = conflate;
                return 0;
            }
            break;

            //  If libgssapi isn't installed, these options provoke EINVAL
#ifdef HAVE_LIBGSSAPI_KRB5
        case ZMQ_GSSAPI_SERVER:
            if (is_int) {
                *value = as_server && mechanism == ZMQ_GSSAPI;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_PRINCIPAL:
            return do_getsockopt (optval_, optvallen_, gss_principal);

        case ZMQ_GSSAPI_SERVICE_PRINCIPAL:
            return do_getsockopt (optval_, optvallen_, gss_service_principal);

        case ZMQ_GSSAPI_PLAINTEXT:
            if (is_int) {
                *value = gss_plaintext;
                return 0;
            }
            break;

        case ZMQ_GSSAPI_PRINCIPAL_NAMETYPE:
            if (is_int) {
                *value = gss_principal_nt;
                return 0;
            }
            break;
        case ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE:
            if (is_int) {
                *value = gss_service_principal_nt;
                return 0;
            }
            break;
#endif

        case ZMQ_HANDSHAKE_IVL:
            if (is_int) {
                *value = handshake_ivl;
                return 0;
            }
            break;

        case ZMQ_INVERT_MATCHING:
            if (is_int) {
                *value = invert_matching;
                return 0;
            }
            break;

        case ZMQ_HEARTBEAT_IVL:
            if (is_int) {
                *value = heartbeat_interval;
                return 0;
            }
            break;

        case ZMQ_HEARTBEAT_TTL:
            if (is_int) {
                // Convert the internal deciseconds value to milliseconds
                *value = heartbeat_ttl * 100;
                return 0;
            }
            break;

        case ZMQ_HEARTBEAT_TIMEOUT:
            if (is_int) {
                *value = heartbeat_timeout;
                return 0;
            }
            break;

        case ZMQ_USE_FD:
            if (is_int) {
                *value = use_fd;
                return 0;
            }
            break;

        case ZMQ_BINDTODEVICE:
            return do_getsockopt (optval_, optvallen_, bound_device);

        case ZMQ_ZAP_ENFORCE_DOMAIN:
            if (is_int) {
                *value = zap_enforce_domain;
                return 0;
            }
            break;

        case ZMQ_LOOPBACK_FASTPATH:
            if (is_int) {
                *value = loopback_fastpath;
                return 0;
            }
            break;

        case ZMQ_MULTICAST_LOOP:
            if (is_int) {
                *value = multicast_loop;
                return 0;
            }
            break;

#ifdef ZMQ_BUILD_DRAFT_API
        case ZMQ_ROUTER_NOTIFY:
            if (is_int) {
                *value = router_notify;
                return 0;
            }
            break;

        case ZMQ_IN_BATCH_SIZE:
            if (is_int) {
                *value = in_batch_size;
                return 0;
            }
            break;

        case ZMQ_OUT_BATCH_SIZE:
            if (is_int) {
                *value = out_batch_size;
                return 0;
            }
            break;

        case ZMQ_PRIORITY:
            if (is_int) {
                *value = priority;
                return 0;
            }
            break;
#endif


        default:
#if defined(ZMQ_ACT_MILITANT)
            malformed = false;
#endif
            break;
    }
#if defined(ZMQ_ACT_MILITANT)
    if (malformed)
        zmq_assert (false);
#endif
    errno = EINVAL;
    return -1;
}
