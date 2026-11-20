/* SPDX-License-Identifier: MPL-2.0 */

#include "precompiled.hpp"
#include "wss_engine.hpp"

#include <gnutls/x509.h>
#include <stdio.h>

static int verify_certificate_callback (gnutls_session_t session)
{
    unsigned int status;
    const char *hostname;

    // read hostname
    hostname = (const char *) gnutls_session_get_ptr (session);

    int rc = gnutls_certificate_verify_peers3 (session, hostname, &status);
    zmq_assert (rc >= 0);

    if (status != 0) {
        // TODO: somehow log the error
        // Certificate is not trusted
        return GNUTLS_E_CERTIFICATE_ERROR;
    }

    // notify gnutls to continue handshake normally
    return 0;
}


zmq::wss_engine_t::wss_engine_t (fd_t fd_,
                                 const options_t &options_,
                                 const endpoint_uri_pair_t &endpoint_uri_pair_,
                                 ws_address_t &address_,
                                 bool client_,
                                 void *tls_server_cred_,
                                 const std::string &hostname_) :
    ws_engine_t (fd_, options_, endpoint_uri_pair_, address_, client_),
    _established (false),
    _tls_client_cred (NULL)
{
    int rc = 0;

    if (client_) {
        // TODO: move to session_base, to allow changing the socket options between connect calls
        rc = gnutls_certificate_allocate_credentials (&_tls_client_cred);
        zmq_assert (rc == 0);

        if (options_.wss_trust_system)
            gnutls_certificate_set_x509_system_trust (_tls_client_cred);

        if (options_.wss_trust_pem.length () > 0) {
            gnutls_datum_t trust = {
              (unsigned char *) options_.wss_trust_pem.c_str (),
              (unsigned int) options_.wss_trust_pem.length ()};
            rc = gnutls_certificate_set_x509_trust_mem (
              _tls_client_cred, &trust, GNUTLS_X509_FMT_PEM);
            zmq_assert (rc >= 0);
        }

        // mTLS: present a client certificate if one was configured. Reuses
        // ZMQ_WSS_CERT_PEM / ZMQ_WSS_KEY_PEM, which previously only applied
        // to listener sockets.
        if (options_.wss_cert_pem.length () > 0
            && options_.wss_key_pem.length () > 0) {
            gnutls_datum_t cert = {
              (unsigned char *) options_.wss_cert_pem.c_str (),
              (unsigned int) options_.wss_cert_pem.length ()};
            gnutls_datum_t key = {
              (unsigned char *) options_.wss_key_pem.c_str (),
              (unsigned int) options_.wss_key_pem.length ()};
            rc = gnutls_certificate_set_x509_key_mem (
              _tls_client_cred, &cert, &key, GNUTLS_X509_FMT_PEM);
            zmq_assert (rc >= 0);
        }

        gnutls_certificate_set_verify_function (_tls_client_cred,
                                                verify_certificate_callback);

        rc = gnutls_init (&_tls_session, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
        zmq_assert (rc == GNUTLS_E_SUCCESS);

        if (!hostname_.empty ())
            gnutls_server_name_set (_tls_session, GNUTLS_NAME_DNS,
                                    hostname_.c_str (), hostname_.size ());

        gnutls_session_set_ptr (
          _tls_session,
          hostname_.empty () ? NULL : const_cast<char *> (hostname_.c_str ()));

        rc = gnutls_credentials_set (_tls_session, GNUTLS_CRD_CERTIFICATE,
                                     _tls_client_cred);
        zmq_assert (rc == GNUTLS_E_SUCCESS);
    } else {
        zmq_assert (tls_server_cred_);

        rc = gnutls_init (&_tls_session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
        zmq_assert (rc == GNUTLS_E_SUCCESS);

        rc = gnutls_credentials_set (_tls_session, GNUTLS_CRD_CERTIFICATE,
                                     tls_server_cred_);
        zmq_assert (rc == GNUTLS_E_SUCCESS);

        // mTLS: require a client cert and have GnuTLS validate the chain
        // against the trust bundle loaded on the listener's credentials.
        // The handshake will fail if the client presents nothing, or
        // presents a cert that doesn't chain to a trusted CA.
        if (options_.wss_require_client_cert) {
            gnutls_certificate_server_set_request (_tls_session,
                                                   GNUTLS_CERT_REQUIRE);
        }
    }

    gnutls_set_default_priority (_tls_session);
    gnutls_transport_set_int (_tls_session, fd_);
}

zmq::wss_engine_t::~wss_engine_t ()
{
    gnutls_deinit (_tls_session);

    if (_tls_client_cred)
        gnutls_certificate_free_credentials (_tls_client_cred);
}

void zmq::wss_engine_t::plug_internal ()
{
    set_pollin ();
    in_event ();
}

void zmq::wss_engine_t::out_event ()
{
    if (_established)
        return ws_engine_t::out_event ();

    do_handshake ();
}

bool zmq::wss_engine_t::do_handshake ()
{
    int rc = gnutls_handshake (_tls_session);

    reset_pollout ();

    if (rc == GNUTLS_E_SUCCESS) {
        capture_peer_cert_properties ();
        start_ws_handshake ();
        _established = true;
        return false;
    } else if (rc == GNUTLS_E_AGAIN) {
        int direction = gnutls_record_get_direction (_tls_session);
        if (direction == 1)
            set_pollout ();

        return false;
    } else if (rc == GNUTLS_E_INTERRUPTED
               || rc == GNUTLS_E_WARNING_ALERT_RECEIVED) {
        return false;
    } else {
        error (zmq::i_engine::connection_error);
        return false;
    }

    return true;
}

bool zmq::wss_engine_t::handshake ()
{
    if (!_established) {
        if (!do_handshake ()) {
            return false;
        }
    }

    return ws_engine_t::handshake ();
}

int zmq::wss_engine_t::read (void *data_, size_t size_)
{
    ssize_t rc = gnutls_record_recv (_tls_session, data_, size_);

    if (rc == GNUTLS_E_REHANDSHAKE) {
        gnutls_alert_send (_tls_session, GNUTLS_AL_WARNING,
                           GNUTLS_A_NO_RENEGOTIATION);
        return 0;
    }

    if (rc == GNUTLS_E_INTERRUPTED) {
        errno = EINTR;
        return -1;
    }

    if (rc == GNUTLS_E_AGAIN) {
        errno = EAGAIN;
        return -1;
    }

    if (rc == 0) {
        errno = EPIPE;
        return -1;
    }

    if (rc < 0) {
        errno = EINVAL;
        return -1;
    }

    // TODO: change return type to ssize_t (signed)
    return rc;
}

int zmq::wss_engine_t::write (const void *data_, size_t size_)
{
    ssize_t rc = gnutls_record_send (_tls_session, data_, size_);

    if (rc == GNUTLS_E_INTERRUPTED || rc == GNUTLS_E_AGAIN) {
        return 0;
    }

    if (rc < 0) {
        errno = EINVAL;
        return -1;
    }

    // TODO: change return type to ssize_t (signed)
    return rc;
}

void zmq::wss_engine_t::capture_peer_cert_properties ()
{
    unsigned int cert_list_size = 0;
    const gnutls_datum_t *cert_list =
      gnutls_certificate_get_peers (_tls_session, &cert_list_size);
    if (!cert_list || cert_list_size == 0)
        return;

    gnutls_x509_crt_t crt;
    if (gnutls_x509_crt_init (&crt) < 0)
        return;
    if (gnutls_x509_crt_import (crt, &cert_list[0], GNUTLS_X509_FMT_DER) < 0) {
        gnutls_x509_crt_deinit (crt);
        return;
    }

    char buf[512];

    // Subject CN
    size_t buf_size = sizeof (buf);
    if (gnutls_x509_crt_get_dn_by_oid (crt, GNUTLS_OID_X520_COMMON_NAME, 0, 0,
                                       buf, &buf_size)
        >= 0) {
        _peer_cert_cn.assign (buf, buf_size);
    }

    // SAN: DNS + URI (joined with "," per type)
    for (int i = 0;; ++i) {
        size_t san_size = sizeof (buf);
        int san_type =
          gnutls_x509_crt_get_subject_alt_name (crt, i, buf, &san_size, NULL);
        if (san_type < 0)
            break;
        if (san_type == GNUTLS_SAN_DNSNAME) {
            if (!_peer_cert_san_dns.empty ())
                _peer_cert_san_dns.append (",");
            _peer_cert_san_dns.append (buf, san_size);
        } else if (san_type == GNUTLS_SAN_URI) {
            if (!_peer_cert_san_uri.empty ())
                _peer_cert_san_uri.append (",");
            _peer_cert_san_uri.append (buf, san_size);
        }
    }

    // SHA256 fingerprint of DER-encoded leaf cert, hex-encoded.
    unsigned char digest[32];
    size_t digest_size = sizeof (digest);
    if (gnutls_x509_crt_get_fingerprint (crt, GNUTLS_DIG_SHA256, digest,
                                         &digest_size)
        >= 0) {
        char hex[sizeof (digest) * 2 + 1];
        for (size_t i = 0; i < digest_size; ++i)
            snprintf (hex + i * 2, 3, "%02x", digest[i]);
        _peer_cert_sha256.assign (hex, digest_size * 2);
    }

    gnutls_x509_crt_deinit (crt);
}

bool zmq::wss_engine_t::init_properties (properties_t &properties_)
{
    bool rc = ws_engine_t::init_properties (properties_);
    if (!_peer_cert_cn.empty ())
        properties_.ZMQ_MAP_INSERT_OR_EMPLACE (
          std::string ("Peer-Cert-Subject-CN"), _peer_cert_cn);
    if (!_peer_cert_san_dns.empty ())
        properties_.ZMQ_MAP_INSERT_OR_EMPLACE (
          std::string ("Peer-Cert-SAN-DNS"), _peer_cert_san_dns);
    if (!_peer_cert_san_uri.empty ())
        properties_.ZMQ_MAP_INSERT_OR_EMPLACE (
          std::string ("Peer-Cert-SAN-URI"), _peer_cert_san_uri);
    if (!_peer_cert_sha256.empty ())
        properties_.ZMQ_MAP_INSERT_OR_EMPLACE (std::string ("Peer-Cert-SHA256"),
                                               _peer_cert_sha256);
    return rc || !_peer_cert_cn.empty () || !_peer_cert_sha256.empty ();
}
