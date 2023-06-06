/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_VMCI_ADDRESS_HPP_INCLUDED__
#define __ZMQ_VMCI_ADDRESS_HPP_INCLUDED__

#include <string>

#include "platform.hpp"
#include "ctx.hpp"

#if defined(ZMQ_HAVE_VMCI)
#include <vmci_sockets.h>

namespace zmq
{
class vmci_address_t
{
  public:
    vmci_address_t ();
    vmci_address_t (ctx_t *parent_);
    vmci_address_t (const sockaddr *sa, socklen_t sa_len, ctx_t *parent_);

    //  This function sets up the address for VMCI transport.
    int resolve (const char *path_);

    //  The opposite to resolve()
    int to_string (std::string &addr_) const;

#if defined ZMQ_HAVE_WINDOWS
    unsigned short family () const;
#else
    sa_family_t family () const;
#endif
    const sockaddr *addr () const;
    socklen_t addrlen () const;

  private:
    struct sockaddr_vm address;
    ctx_t *parent;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (vmci_address_t)
};
}

#endif

#endif
