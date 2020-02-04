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
