/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_VSOCK_ADDRESS_HPP_INCLUDED__
#define __ZMQ_VSOCK_ADDRESS_HPP_INCLUDED__

#include <string>

#include "platform.hpp"
#include "ctx.hpp"

#if defined(ZMQ_HAVE_VSOCK)

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#if defined ZMQ_HAVE_WINDOWS
#ifndef _UAPI_VM_SOCKETS_H
struct sockaddr_vsock
{
#if (_WIN32_WINNT < 0x0600)
    UINT16 svm_family;
#else
    ADDRESS_FAMILY svm_family;
#endif
    UINT16 svm_reserved1;
    UINT32 svm_port;
    UINT32 svm_cid;
    UINT8 svm_flags;
    UINT8 svm_zero[sizeof (struct sockaddr) - sizeof (svm_family)
                   - sizeof (svm_reserved1) - sizeof (svm_port)
                   - sizeof (svm_cid) - sizeof (svm_flags)];
};

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY (~(0U))
#endif

#ifndef VMADDR_PORT_ANY
#define VMADDR_PORT_ANY (~(0U))
#endif

#endif
#else
#include <linux/vm_sockets.h>
#endif

namespace zmq
{
class vsock_address_t
{
  public:
    vsock_address_t ();
    vsock_address_t (ctx_t *parent_);
    vsock_address_t (const sockaddr *sa, socklen_t sa_len, ctx_t *parent_);

    //  This function sets up the address for VSOCK transport.
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

    struct sockaddr_vsock address;
    ctx_t *parent;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (vsock_address_t)
};
}

#endif

#endif
