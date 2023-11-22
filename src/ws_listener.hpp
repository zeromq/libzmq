/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WS_LISTENER_HPP_INCLUDED__
#define __ZMQ_WS_LISTENER_HPP_INCLUDED__

#include "fd.hpp"
#include "ws_address.hpp"
#include "stream_listener_base.hpp"

#if defined ZMQ_USE_MBEDTLS
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined ZMQ_USE_GNUTLS
#include <gnutls/gnutls.h>
#endif

namespace zmq
{
class ws_listener_t ZMQ_FINAL : public stream_listener_base_t
{
  public:
    ws_listener_t (zmq::io_thread_t *io_thread_,
                   zmq::socket_base_t *socket_,
                   const options_t &options_,
                   bool wss_);

    ~ws_listener_t ();

    //  Set address to listen on.
    int set_local_address (const char *addr_);

  protected:
    std::string get_socket_name (fd_t fd_, socket_end_t socket_end_) const;
    void create_engine (fd_t fd);

  private:
    //  Handlers for I/O events.
    void in_event ();

    //  Accept the new connection. Returns the file descriptor of the
    //  newly created connection. The function may return retired_fd
    //  if the connection was dropped while waiting in the listen backlog
    //  or was denied because of accept filters.
    fd_t accept ();

    int create_socket (const char *addr_);

    //  Address to listen on.
    ws_address_t _address;

    bool _wss;
#ifdef ZMQ_HAVE_WSS
#if defined ZMQ_USE_MBEDTLS
    std::unique_ptr<mbedtls_entropy_context> _entropy;
    std::unique_ptr<mbedtls_ctr_drbg_context> _rng;
    std::unique_ptr<mbedtls_ssl_context> _ssl;
    std::unique_ptr<mbedtls_ssl_config> _ssl_config;
    std::unique_ptr<mbedtls_x509_crt> _ssl_ca_cert;
    std::unique_ptr<mbedtls_x509_crt> _ssl_server_cert;
    std::unique_ptr<mbedtls_pk_context> _ssl_server_pkey;
#elif defined ZMQ_USE_GNUTLS
    gnutls_certificate_credentials_t _ssl;
#else
#error "No TLS implementation set"
#endif
#endif

    ZMQ_NON_COPYABLE_NOR_MOVABLE (ws_listener_t)
};
}

#endif
