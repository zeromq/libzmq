/* SPDX-License-Identifier: MPL-2.0 */
#include "precompiled.hpp"

#include "ip.hpp"
#include "vmci.hpp"
#include "vmci_address.hpp"

#if defined ZMQ_HAVE_VMCI

#include <cassert>
#include <vmci_sockets.h>

void zmq::tune_vmci_buffer_size (ctx_t *context_,
                                 fd_t sockfd_,
                                 uint64_t default_size_,
                                 uint64_t min_size_,
                                 uint64_t max_size_)
{
    int family = context_->get_vmci_socket_family ();
    assert (family != -1);

    if (default_size_ != 0) {
        int rc = setsockopt (sockfd_, family, SO_VMCI_BUFFER_SIZE,
                             (char *) &default_size_, sizeof default_size_);
#if defined ZMQ_HAVE_WINDOWS
        wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif
    }

    if (min_size_ != 0) {
        int rc = setsockopt (sockfd_, family, SO_VMCI_BUFFER_SIZE,
                             (char *) &min_size_, sizeof min_size_);
#if defined ZMQ_HAVE_WINDOWS
        wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif
    }

    if (max_size_ != 0) {
        int rc = setsockopt (sockfd_, family, SO_VMCI_BUFFER_SIZE,
                             (char *) &max_size_, sizeof max_size_);
#if defined ZMQ_HAVE_WINDOWS
        wsa_assert (rc != SOCKET_ERROR);
#else
        errno_assert (rc == 0);
#endif
    }
}

#if defined ZMQ_HAVE_WINDOWS
void zmq::tune_vmci_connect_timeout (ctx_t *context_,
                                     fd_t sockfd_,
                                     DWORD timeout_)
#else
void zmq::tune_vmci_connect_timeout (ctx_t *context_,
                                     fd_t sockfd_,
                                     struct timeval timeout_)
#endif
{
    int family = context_->get_vmci_socket_family ();
    assert (family != -1);

    int rc = setsockopt (sockfd_, family, SO_VMCI_CONNECT_TIMEOUT,
                         (char *) &timeout_, sizeof timeout_);
#if defined ZMQ_HAVE_WINDOWS
    wsa_assert (rc != SOCKET_ERROR);
#else
    errno_assert (rc == 0);
#endif
}

zmq::fd_t zmq::vmci_open_socket (const char *address_,
                                 const zmq::options_t &options_,
                                 zmq::vmci_address_t *out_vmci_addr_)
{
    //  Convert the textual address into address structure.
    int rc = out_vmci_addr_->resolve (address_);
    if (rc != 0)
        return retired_fd;

    //  Create the socket.
    fd_t s = open_socket (out_vmci_addr_->family (), SOCK_STREAM, 0);

    if (s == retired_fd) {
        return retired_fd;
    }

    return s;
}

#endif
