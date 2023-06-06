/* SPDX-License-Identifier: MPL-2.0 */

#ifndef __ZMQ_MAILBOX_SAFE_HPP_INCLUDED__
#define __ZMQ_MAILBOX_SAFE_HPP_INCLUDED__

#include <vector>
#include <stddef.h>

#include "signaler.hpp"
#include "fd.hpp"
#include "config.hpp"
#include "command.hpp"
#include "ypipe.hpp"
#include "mutex.hpp"
#include "i_mailbox.hpp"
#include "condition_variable.hpp"

namespace zmq
{
class mailbox_safe_t ZMQ_FINAL : public i_mailbox
{
  public:
    mailbox_safe_t (mutex_t *sync_);
    ~mailbox_safe_t ();

    void send (const command_t &cmd_);
    int recv (command_t *cmd_, int timeout_);

    // Add signaler to mailbox which will be called when a message is ready
    void add_signaler (signaler_t *signaler_);
    void remove_signaler (signaler_t *signaler_);
    void clear_signalers ();

#ifdef HAVE_FORK
    // close the file descriptors in the signaller. This is used in a forked
    // child process to close the file descriptors so that they do not interfere
    // with the context in the parent process.
    void forked () ZMQ_FINAL
    {
        // TODO: call fork on the condition variable
    }
#endif

  private:
    //  The pipe to store actual commands.
    typedef ypipe_t<command_t, command_pipe_granularity> cpipe_t;
    cpipe_t _cpipe;

    //  Condition variable to pass signals from writer thread to reader thread.
    condition_variable_t _cond_var;

    //  Synchronize access to the mailbox from receivers and senders
    mutex_t *const _sync;

    std::vector<zmq::signaler_t *> _signalers;

    ZMQ_NON_COPYABLE_NOR_MOVABLE (mailbox_safe_t)
};
}

#endif
