/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_WSS_ENGINE_HPP_INCLUDED__
#define __ZMQ_WSS_ENGINE_HPP_INCLUDED__

#include <gnutls/gnutls.h>
#include "ws_engine.hpp"

#define WSS_BUFFER_SIZE 8192

namespace zmq
{
class wss_engine_t : public ws_engine_t
{
  public:
    wss_engine_t (fd_t fd_,
                  const options_t &options_,
                  const endpoint_uri_pair_t &endpoint_uri_pair_,
                  ws_address_t &address_,
                  bool client_,
                  void *tls_server_cred_,
                  const std::string &hostname_);
    ~wss_engine_t ();

    void out_event ();

  protected:
    bool handshake ();
    void plug_internal ();
    int read (void *data, size_t size_);
    int write (const void *data_, size_t size_);
    bool init_properties (properties_t &properties_);

  private:
    bool do_handshake ();
    void capture_peer_cert_properties ();

    bool _established;
    gnutls_certificate_credentials_t _tls_client_cred;
    gnutls_session_t _tls_session;

    // Captured from the peer's X.509 cert on handshake success. Empty if the
    // peer did not present a cert (e.g. mTLS was not required). Exposed to
    // the application via zmq_msg_gets() as Peer-Cert-* properties.
    std::string _peer_cert_cn;
    std::string _peer_cert_san_dns;
    std::string _peer_cert_san_uri;
    std::string _peer_cert_sha256;
};
}

#endif
