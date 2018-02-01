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

#ifdef HAVE_LIBGSSAPI_KRB5

#include <string.h>
#include <string>

#include "msg.hpp"
#include "session_base.hpp"
#include "err.hpp"
#include "gssapi_mechanism_base.hpp"
#include "wire.hpp"

zmq::gssapi_mechanism_base_t::gssapi_mechanism_base_t (
  session_base_t *session_, const options_t &options_) :
    mechanism_base_t (session_, options_),
    send_tok (),
    recv_tok (),
    /// FIXME remove? in_buf (),
    target_name (GSS_C_NO_NAME),
    principal_name (NULL),
    maj_stat (GSS_S_COMPLETE),
    min_stat (0),
    init_sec_min_stat (0),
    ret_flags (0),
    gss_flags (GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG),
    cred (GSS_C_NO_CREDENTIAL),
    context (GSS_C_NO_CONTEXT),
    do_encryption (!options_.gss_plaintext)
{
}

zmq::gssapi_mechanism_base_t::~gssapi_mechanism_base_t ()
{
    if (target_name)
        gss_release_name (&min_stat, &target_name);
    if (context)
        gss_delete_sec_context (&min_stat, &context, GSS_C_NO_BUFFER);
}

int zmq::gssapi_mechanism_base_t::encode_message (msg_t *msg_)
{
    // Wrap the token value
    int state;
    gss_buffer_desc plaintext;
    gss_buffer_desc wrapped;

    uint8_t flags = 0;
    if (msg_->flags () & msg_t::more)
        flags |= 0x01;
    if (msg_->flags () & msg_t::command)
        flags |= 0x02;

    uint8_t *plaintext_buffer =
      static_cast<uint8_t *> (malloc (msg_->size () + 1));
    alloc_assert (plaintext_buffer);

    plaintext_buffer[0] = flags;
    memcpy (plaintext_buffer + 1, msg_->data (), msg_->size ());

    plaintext.value = plaintext_buffer;
    plaintext.length = msg_->size () + 1;

    maj_stat = gss_wrap (&min_stat, context, 1, GSS_C_QOP_DEFAULT, &plaintext,
                         &state, &wrapped);

    zmq_assert (maj_stat == GSS_S_COMPLETE);
    zmq_assert (state);

    // Re-initialize msg_ for wrapped text
    int rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (8 + 4 + wrapped.length);
    zmq_assert (rc == 0);

    uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());

    // Add command string
    memcpy (ptr, "\x07MESSAGE", 8);
    ptr += 8;

    // Add token length
    put_uint32 (ptr, static_cast<uint32_t> (wrapped.length));
    ptr += 4;

    // Add wrapped token value
    memcpy (ptr, wrapped.value, wrapped.length);
    ptr += wrapped.length;

    gss_release_buffer (&min_stat, &wrapped);

    return 0;
}

int zmq::gssapi_mechanism_base_t::decode_message (msg_t *msg_)
{
    const uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    // Get command string
    if (bytes_left < 8 || memcmp (ptr, "\x07MESSAGE", 8)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 8;
    bytes_left -= 8;

    // Get token length
    if (bytes_left < 4) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }
    gss_buffer_desc wrapped;
    wrapped.length = get_uint32 (ptr);
    ptr += 4;
    bytes_left -= 4;

    // Get token value
    if (bytes_left < wrapped.length) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }
    // TODO: instead of malloc/memcpy, can we just do: wrapped.value = ptr;
    const size_t alloc_length = wrapped.length ? wrapped.length : 1;
    wrapped.value = static_cast<char *> (malloc (alloc_length));
    alloc_assert (wrapped.value);

    if (wrapped.length) {
        memcpy (wrapped.value, ptr, wrapped.length);
        ptr += wrapped.length;
        bytes_left -= wrapped.length;
    }

    // Unwrap the token value
    int state;
    gss_buffer_desc plaintext;
    maj_stat = gss_unwrap (&min_stat, context, &wrapped, &plaintext, &state,
                           (gss_qop_t *) NULL);

    if (maj_stat != GSS_S_COMPLETE) {
        gss_release_buffer (&min_stat, &plaintext);
        free (wrapped.value);
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        errno = EPROTO;
        return -1;
    }
    zmq_assert (state);

    // Re-initialize msg_ for plaintext
    rc = msg_->close ();
    zmq_assert (rc == 0);

    rc = msg_->init_size (plaintext.length - 1);
    zmq_assert (rc == 0);

    const uint8_t flags = static_cast<char *> (plaintext.value)[0];
    if (flags & 0x01)
        msg_->set_flags (msg_t::more);
    if (flags & 0x02)
        msg_->set_flags (msg_t::command);

    memcpy (msg_->data (), static_cast<char *> (plaintext.value) + 1,
            plaintext.length - 1);

    gss_release_buffer (&min_stat, &plaintext);
    free (wrapped.value);

    if (bytes_left > 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int zmq::gssapi_mechanism_base_t::produce_initiate (msg_t *msg_,
                                                    void *token_value_,
                                                    size_t token_length_)
{
    zmq_assert (token_value_);
    zmq_assert (token_length_ <= 0xFFFFFFFFUL);

    const size_t command_size = 9 + 4 + token_length_;

    const int rc = msg_->init_size (command_size);
    errno_assert (rc == 0);

    uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());

    // Add command string
    memcpy (ptr, "\x08INITIATE", 9);
    ptr += 9;

    // Add token length
    put_uint32 (ptr, static_cast<uint32_t> (token_length_));
    ptr += 4;

    // Add token value
    memcpy (ptr, token_value_, token_length_);
    ptr += token_length_;

    return 0;
}

int zmq::gssapi_mechanism_base_t::process_initiate (msg_t *msg_,
                                                    void **token_value_,
                                                    size_t &token_length_)
{
    zmq_assert (token_value_);

    const uint8_t *ptr = static_cast<uint8_t *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    // Get command string
    if (bytes_left < 9 || memcmp (ptr, "\x08INITIATE", 9)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 9;
    bytes_left -= 9;

    // Get token length
    if (bytes_left < 4) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }
    token_length_ = get_uint32 (ptr);
    ptr += 4;
    bytes_left -= 4;

    // Get token value
    if (bytes_left < token_length_) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }

    *token_value_ =
      static_cast<char *> (malloc (token_length_ ? token_length_ : 1));
    alloc_assert (*token_value_);

    if (token_length_) {
        memcpy (*token_value_, ptr, token_length_);
        ptr += token_length_;
        bytes_left -= token_length_;
    }

    if (bytes_left > 0) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (),
          ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        errno = EPROTO;
        return -1;
    }

    return 0;
}

int zmq::gssapi_mechanism_base_t::produce_ready (msg_t *msg_)
{
    make_command_with_basic_properties (msg_, "\5READY", 6);

    if (do_encryption)
        return encode_message (msg_);

    return 0;
}

int zmq::gssapi_mechanism_base_t::process_ready (msg_t *msg_)
{
    if (do_encryption) {
        const int rc = decode_message (msg_);
        if (rc != 0)
            return rc;
    }

    const unsigned char *ptr = static_cast<unsigned char *> (msg_->data ());
    size_t bytes_left = msg_->size ();

    int rc = check_basic_command_structure (msg_);
    if (rc == -1)
        return rc;

    if (bytes_left < 6 || memcmp (ptr, "\x05READY", 6)) {
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        errno = EPROTO;
        return -1;
    }
    ptr += 6;
    bytes_left -= 6;
    rc = parse_metadata (ptr, bytes_left);
    if (rc == -1)
        session->get_socket ()->event_handshake_failed_protocol (
          session->get_endpoint (), ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);

    return rc;
}

const gss_OID zmq::gssapi_mechanism_base_t::convert_nametype (int zmq_nametype)
{
    switch (zmq_nametype) {
        case ZMQ_GSSAPI_NT_HOSTBASED:
            return GSS_C_NT_HOSTBASED_SERVICE;
        case ZMQ_GSSAPI_NT_USER_NAME:
            return GSS_C_NT_USER_NAME;
        case ZMQ_GSSAPI_NT_KRB5_PRINCIPAL:
#ifdef GSS_KRB5_NT_PRINCIPAL_NAME
            return (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME;
#else
            return GSS_C_NT_USER_NAME;
#endif
    }
    return NULL;
}

int zmq::gssapi_mechanism_base_t::acquire_credentials (char *service_name_,
                                                       gss_cred_id_t *cred_,
                                                       gss_OID name_type_)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_name_t server_name;

    gss_buffer_desc name_buf;
    name_buf.value = service_name_;
    name_buf.length = strlen ((char *) name_buf.value) + 1;

    maj_stat = gss_import_name (&min_stat, &name_buf, name_type_, &server_name);

    if (maj_stat != GSS_S_COMPLETE)
        return -1;

    maj_stat = gss_acquire_cred (&min_stat, server_name, 0, GSS_C_NO_OID_SET,
                                 GSS_C_BOTH, cred_, NULL, NULL);

    if (maj_stat != GSS_S_COMPLETE)
        return -1;

    gss_release_name (&min_stat, &server_name);

    return 0;
}

#endif
