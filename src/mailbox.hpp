/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MAILBOX_HPP_INCLUDED__
#define __ZMQ_MAILBOX_HPP_INCLUDED__

#include <stddef.h>

#include "signaler.hpp"
#include "fd.hpp"
#include "config.hpp"
#include "command.hpp"
#include "ypipe.hpp"
#include "mutex.hpp"
#include "i_mailbox.hpp"

namespace zmq
{
class mailbox_t ZMQ_FINAL : public i_mailbox
{
  public:
    mailbox_t ();
    ~mailbox_t ();

    fd_t get_fd () const;
    void send (const command_t &cmd_);
    int recv (command_t *cmd_, int timeout_);

    bool valid () const;

#ifdef HAVE_FORK
    // close the file descriptors in the signaller. This is used in a forked
    // child process to close the file descriptors so that they do not interfere
    // with the context in the parent process.
    void forked () ZMQ_FINAL { _signaler.forked (); }
#endif

  private:
    //  The pipe to store actual commands.
    typedef ypipe_t<command_t, command_pipe_granularity> cpipe_t;
    cpipe_t _cpipe;

    //  Signaler to pass signals from writer thread to reader thread.
    signaler_t _signaler;

    //  There's only one thread receiving from the mailbox, but there
    //  is arbitrary number of threads sending. Given that ypipe requires
    //  synchronised access on both of its endpoints, we have to synchronise
    //  the sending side.
    mutex_t _sync;

    //  True if the underlying pipe is active, ie. when we are allowed to
    //  read commands from it.
    bool _active;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (mailbox_t)
};
}

#endif
