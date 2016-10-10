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
#include <sys/types.h>

#include "err.hpp"
#include "socks.hpp"
#include "tcp.hpp"

#ifndef ZMQ_HAVE_WINDOWS
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

zmq::socks_greeting_t::socks_greeting_t (uint8_t method_) :
    num_methods (1)
{
    methods [0] = method_;
}

zmq::socks_greeting_t::socks_greeting_t (
    uint8_t *methods_, uint8_t num_methods_)
    : num_methods (num_methods_)
{
    for (uint8_t i = 0; i < num_methods_; i++)
        methods [i] = methods_ [i];
}

zmq::socks_greeting_encoder_t::socks_greeting_encoder_t ()
    : bytes_encoded (0), bytes_written (0)
{}

void zmq::socks_greeting_encoder_t::encode (const socks_greeting_t &greeting_)
{
    uint8_t *ptr = buf;

    *ptr++ = 0x05;
    *ptr++ = (uint8_t) greeting_.num_methods;
    for (uint8_t i = 0; i < greeting_.num_methods; i++)
        *ptr++ = greeting_.methods [i];

    bytes_encoded = 2 + greeting_.num_methods;
    bytes_written = 0;
}

int zmq::socks_greeting_encoder_t::output (fd_t fd_)
{
    const int rc = tcp_write (
        fd_, buf + bytes_written, bytes_encoded - bytes_written);
    if (rc > 0)
        bytes_written += static_cast <size_t> (rc);
    return rc;
}

bool zmq::socks_greeting_encoder_t::has_pending_data () const
{
    return bytes_written < bytes_encoded;
}

void zmq::socks_greeting_encoder_t::reset ()
{
    bytes_encoded = bytes_written = 0;
}

zmq::socks_choice_t::socks_choice_t (unsigned char method_)
    : method (method_)
{}

zmq::socks_choice_decoder_t::socks_choice_decoder_t ()
    : bytes_read (0)
{}

int zmq::socks_choice_decoder_t::input (fd_t fd_)
{
    zmq_assert (bytes_read < 2);
    const int rc = tcp_read (fd_, buf + bytes_read, 2 - bytes_read);
    if (rc > 0) {
        bytes_read += static_cast <size_t> (rc);
        if (buf [0] != 0x05)
            return -1;
    }
    return rc;
}

bool zmq::socks_choice_decoder_t::message_ready () const
{
    return bytes_read == 2;
}

zmq::socks_choice_t zmq::socks_choice_decoder_t::decode ()
{
    zmq_assert (message_ready ());
    return socks_choice_t (buf [1]);
}

void zmq::socks_choice_decoder_t::reset ()
{
    bytes_read = 0;
}


zmq::socks_request_t::socks_request_t (
        uint8_t command_, std::string hostname_, uint16_t port_)
    : command (command_), hostname (hostname_), port (port_)
{
    zmq_assert (hostname_.size () <= UINT8_MAX);
}

zmq::socks_request_encoder_t::socks_request_encoder_t ()
    : bytes_encoded (0), bytes_written (0)
{}

void zmq::socks_request_encoder_t::encode (const socks_request_t &req)
{
    zmq_assert (req.hostname.size() <= UINT8_MAX);

    unsigned char *ptr = buf;
    *ptr++ = 0x05;
    *ptr++ = req.command;
    *ptr++ = 0x00;

#if defined ZMQ_HAVE_OPENVMS && defined __ia64 && __INITIAL_POINTER_SIZE == 64
    __addrinfo64 hints, *res = NULL;
#else
    addrinfo hints, *res = NULL;
#endif

    memset (&hints, 0, sizeof hints);

    //  Suppress potential DNS lookups.
    hints.ai_flags = AI_NUMERICHOST;

    const int rc = getaddrinfo (req.hostname.c_str (), NULL, &hints, &res);
    if (rc == 0 && res->ai_family == AF_INET) {
        struct sockaddr_in *sockaddr_in =
            reinterpret_cast <struct sockaddr_in *> (res->ai_addr);
        *ptr++ = 0x01;
        memcpy (ptr, &sockaddr_in->sin_addr, 4);
        ptr += 4;
    }
    else
    if (rc == 0 && res->ai_family == AF_INET6) {
        struct sockaddr_in6 *sockaddr_in6 =
            reinterpret_cast <struct sockaddr_in6 *> (res->ai_addr);
        *ptr++ = 0x04;
        memcpy (ptr, &sockaddr_in6->sin6_addr, 16);
        ptr += 16;
    }
    else {
        *ptr++ = 0x03;
        *ptr++ = (unsigned char) req.hostname.size ();
        memcpy (ptr, req.hostname.c_str (), req.hostname.size ());
        ptr += req.hostname.size ();
    }

    if (rc == 0)
        freeaddrinfo (res);

    *ptr++ = req.port / 256;
    *ptr++ = req.port % 256;

    bytes_encoded = ptr - buf;
    bytes_written = 0;
}

int zmq::socks_request_encoder_t::output (fd_t fd_)
{
    const int rc = tcp_write (
        fd_, buf + bytes_written, bytes_encoded - bytes_written);
    if (rc > 0)
        bytes_written += static_cast <size_t> (rc);
    return rc;
}

bool zmq::socks_request_encoder_t::has_pending_data () const
{
    return bytes_written < bytes_encoded;
}

void zmq::socks_request_encoder_t::reset ()
{
    bytes_encoded = bytes_written = 0;
}

zmq::socks_response_t::socks_response_t (
        uint8_t response_code_, std::string address_, uint16_t port_)
    : response_code (response_code_), address (address_), port (port_)
{}

zmq::socks_response_decoder_t::socks_response_decoder_t ()
    : bytes_read (0)
{}

int zmq::socks_response_decoder_t::input (fd_t fd_)
{
    size_t n = 0;

    if (bytes_read < 5)
        n = 5 - bytes_read;
    else {
        const uint8_t atyp = buf [3];
        zmq_assert (atyp == 0x01 || atyp == 0x03 || atyp == 0x04);
        if (atyp == 0x01)
            n = 3 + 2;
        else
        if (atyp == 0x03)
            n = buf [4] + 2;
        else
        if (atyp == 0x04)
            n = 15 + 2;
    }
    const int rc = tcp_read (fd_, buf + bytes_read, n);
    if (rc > 0) {
        bytes_read += static_cast <size_t> (rc);
        if (buf [0] != 0x05)
            return -1;
        if (bytes_read >= 2)
            if (buf [1] > 0x08)
                return -1;
        if (bytes_read >= 3)
            if (buf [2] != 0x00)
                return -1;
        if (bytes_read >= 4) {
            const uint8_t atyp = buf [3];
            if (atyp != 0x01 && atyp != 0x03 && atyp != 0x04)
                return -1;
        }
    }
    return rc;
}

bool zmq::socks_response_decoder_t::message_ready () const
{
    if (bytes_read < 4)
        return false;
    else {
        const uint8_t atyp = buf [3];
        zmq_assert (atyp == 0x01 || atyp == 0x03 || atyp == 0x04);
        if (atyp == 0x01)
            return bytes_read == 10;
        else
        if (atyp == 0x03)
            return bytes_read > 4 && bytes_read == 4 + 1 + buf [4] + 2u;
        else
            return bytes_read == 22;
    }
}

zmq::socks_response_t zmq::socks_response_decoder_t::decode ()
{
    zmq_assert (message_ready ());
    return socks_response_t (buf [1], "", 0);
}

void zmq::socks_response_decoder_t::reset ()
{
    bytes_read = 0;
}
