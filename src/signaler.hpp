/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_SIGNALER_HPP_INCLUDED__
#define __ZMQ_SIGNALER_HPP_INCLUDED__

#ifdef HAVE_FORK
#include <unistd.h>
#endif

#include "fd.hpp"
#include "macros.hpp"

namespace zmq
{
//  This is a cross-platform equivalent to signal_fd. However, as opposed
//  to signal_fd there can be at most one signal in the signaler at any
//  given moment. Attempt to send a signal before receiving the previous
//  one will result in undefined behaviour.

class signaler_t
{
  public:
    signaler_t ();
    ~signaler_t ();

    // Returns the socket/file descriptor
    // May return retired_fd if the signaler could not be initialized.
    fd_t get_fd () const;
    void send ();
    int wait (int timeout_) const;
    void recv ();
    int recv_failable ();

    bool valid () const;

#ifdef HAVE_FORK
    // close the file descriptors in a forked child process so that they
    // do not interfere with the context in the parent process.
    void forked ();
#endif

  private:
    //  Underlying write & read file descriptor
    //  Will be -1 if an error occurred during initialization, e.g. we
    //  exceeded the number of available handles
    fd_t _w;
    fd_t _r;

#ifdef HAVE_FORK
    // the process that created this context. Used to detect forking.
    pid_t pid;
    // idempotent close of file descriptors that is safe to use by destructor
    // and forked().
    void close_internal ();
#endif

    ZMQ_NON_COPYABLE_NOR_MOVABLE (signaler_t)
};
}

#endif
