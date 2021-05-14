/*
Copyright (c) 2007-2019 Contributors as noted in the AUTHORS file

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
#include "wss_engine.hpp"

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

    if (rc == GNUTLS_E_INTERRUPTED) {
        errno = EINTR;
        return -1;
    }

    if (rc == GNUTLS_E_AGAIN) {
        errno = EAGAIN;
        return -1;
    }

    if (rc < 0) {
        errno = EINVAL;
        return -1;
    }

    // TODO: change return type to ssize_t (signed)
    return rc;
}
